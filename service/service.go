package service

/*
Service for a Proof-of-Personhood party

Proof-of-personhood parties provide a number of "attendees" with an "anonymous
token" that enables them to "authenticate" to a service as being part of the
party.

These parties are held by a number of "organisers" who set up a party by
defining place, time and purpose of that party and by publishing a
"party configuration" that is signed by the organisers "conodes".
At the party, they "register" all attendees' public keys.
Once the party is over, they create a "party transcript" that is signed by all
organisers' conodes.

The attendees create their "pop token" by joining their private key to the
party transcript. They can now use that token to sign a "message" in a "context"
from a service and send the resulting "signature" and "tag" back to the service.

On the service's side, it can use the party transcript to verify that the
signature has been created using a private key present in the party transcript.
The tag will be unique to that attendee/context pair, but another service using
another context will not be able to link two tags to the same or different
attendee.
*/

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/dedis/cothority.v1/bftcosi"
	"gopkg.in/dedis/cothority.v1/messaging"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

// Name is the name to refer to the Template service from another
// package.
const Name = "PoPServer"
const cfgName = "pop.bin"
const bftSignFinal = "BFTFinal"
const bftSignMerge = "PopBFTSignMerge"

const TIMEOUT = 60 * time.Second
const DELIMETER = "; "

var checkConfigID network.MessageTypeID
var checkConfigReplyID network.MessageTypeID
var mergeConfigID network.MessageTypeID
var mergeConfigReplyID network.MessageTypeID
var mergeCheckID network.MessageTypeID
var mergeCheckReplyID network.MessageTypeID

func init() {
	onet.RegisterNewService(Name, newService)
	network.RegisterMessage(&saveData{})
	checkConfigID = network.RegisterMessage(CheckConfig{})
	checkConfigReplyID = network.RegisterMessage(CheckConfigReply{})
	mergeConfigID = network.RegisterMessage(MergeConfig{})
	mergeConfigReplyID = network.RegisterMessage(MergeConfigReply{})
	mergeCheckID = network.RegisterMessage(MergeCheck{})
	mergeCheckReplyID = network.RegisterMessage(MergeCheckReply{})
}

// Service represents data needed for one pop-party.
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	path string
	data *saveData
	// propagate final message
	Propagate messaging.PropagationFunc
}

type saveData struct {
	// Pin holds the randomly chosen pin
	Pin string
	// Public key of linked pop
	Public abstract.Point
	// The final statements
	Finals map[string]*FinalStatement
	// The meta info used in merge process
	mergeMetas map[string]*mergeMeta
	// Sync tools
	syncMetas map[string]*syncMeta
}

type mergeMeta struct {
	// Map of final statements of parties that are going to be merged together
	statementsMap map[string]*FinalStatement
	// Flag tells that message distribution has already started
	distrib bool
}

func newmergeMeta() *mergeMeta {
	mm := &mergeMeta{}
	mm.statementsMap = make(map[string]*FinalStatement)
	mm.distrib = false
	return mm
}

type syncMeta struct {
	// channel to return the configreply
	ccChannel chan *CheckConfigReply
	// channel to return the mergereply
	mcChannel chan *MergeConfigReply
	// group waits responses after broadcast
	mcGroup *sync.WaitGroup
}

// PinRequest prints out a pin if none is given, else it verifies it has the
// correct pin, and if so, it stores the public key as reference.
// TODO: resolve organizers and clients(asking for update)
func (s *Service) PinRequest(req *PinRequest) (network.Message, onet.ClientError) {
	if req.Pin == "" {
		s.data.Pin = fmt.Sprintf("%06d", random.Int(big.NewInt(1000000), random.Stream))
		log.Info("PIN:", s.data.Pin)
		return nil, onet.NewClientErrorCode(ErrorWrongPIN, "Read PIN in server-log")
	}
	if req.Pin != s.data.Pin {
		return nil, onet.NewClientErrorCode(ErrorWrongPIN, "Wrong PIN")
	}
	s.data.Public = req.Public
	s.save()
	log.Lvl1("Successfully registered PIN/Public", s.data.Pin, req.Public)
	return nil, nil
}

// StoreConfig saves the pop-config locally
func (s *Service) StoreConfig(req *StoreConfig) (network.Message, onet.ClientError) {
	log.Lvlf2("StoreConfig: %s %v %x", s.Context.ServerIdentity(), req.Desc, req.Desc.Hash())
	if req.Desc.Roster == nil {
		return nil, onet.NewClientErrorCode(ErrorInternal, "no roster set")
	}
	if s.data.Public == nil {
		return nil, onet.NewClientErrorCode(ErrorInternal, "Not linked yet")
	}
	hash := req.Desc.Hash()
	if err := crypto.VerifySchnorr(network.Suite, s.data.Public, hash, req.Signature); err != nil {
		return nil, onet.NewClientErrorCode(ErrorInternal, "Invalid signature"+err.Error())
	}
	s.data.Finals[string(hash)] = &FinalStatement{Desc: req.Desc, Signature: []byte{}}
	s.data.syncMetas[string(hash)] = &syncMeta{
		ccChannel: make(chan *CheckConfigReply, 1),
		mcChannel: make(chan *MergeConfigReply, 1),
		mcGroup:   &sync.WaitGroup{},
	}
	if len(req.Desc.Parties) > 0 {
		meta := newmergeMeta()
		s.data.mergeMetas[string(hash)] = meta
		// party is merged with itself already
		meta.statementsMap[string(hash)] = s.data.Finals[string(hash)]
	}
	s.save()
	return &StoreConfigReply{hash}, nil
}

// FinalizeRequest returns the FinalStatement if all conodes already received
// a PopDesc and signed off. The FinalStatement holds the updated PopDesc, the
// pruned attendees-public-key-list and the collective signature.
func (s *Service) FinalizeRequest(req *FinalizeRequest) (network.Message, onet.ClientError) {
	log.Lvlf2("Finalize: %s %+v", s.Context.ServerIdentity(), req)
	if s.data.Public == nil {
		return nil, onet.NewClientErrorCode(ErrorInternal, "Not linked yet")
	}
	hash, err := req.Hash()
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	if err := crypto.VerifySchnorr(network.Suite, s.data.Public, hash, req.Signature); err != nil {
		return nil, onet.NewClientErrorCode(ErrorInternal, "Invalid signature:"+err.Error())
	}

	var final *FinalStatement
	var ok bool
	if final, ok = s.data.Finals[string(req.DescID)]; !ok || final == nil || final.Desc == nil {
		return nil, onet.NewClientErrorCode(ErrorInternal, "No config found")
	}
	if final.Verify() == nil {
		log.Lvl2("Sending known final statement")
		return &FinalizeResponse{final}, nil
	}

	// Contact all other nodes and ask them if they already have a config.
	final.Attendees = make([]abstract.Point, len(req.Attendees))
	copy(final.Attendees, req.Attendees)
	cc := &CheckConfig{final.Desc.Hash(), req.Attendees}
	for _, c := range final.Desc.Roster.List {
		if !c.ID.Equal(s.ServerIdentity().ID) {
			log.Lvl2("Contacting", c, cc.Attendees)
			err := s.SendRaw(c, cc)
			if err != nil {
				return nil, onet.NewClientErrorCode(ErrorInternal, err.Error())
			}
			if syncData, ok := s.data.syncMetas[string(req.DescID)]; ok {
				rep := <-syncData.ccChannel
				if rep == nil {
					return nil, onet.NewClientErrorCode(ErrorOtherFinals,
						"Not all other conodes finalized yet")
				}
			}
		}
	}

	// Create signature and propagate it
	cerr := s.signAndPropagateFinal(final)
	if cerr != nil {
		return nil, cerr
	}
	return &FinalizeResponse{final}, nil
}

func (s *Service) bftVerifyFinal(Msg []byte, Data []byte) bool {
	final, err := NewFinalStatementFromToml(Data)
	if err != nil {
		log.Error(err.Error())
		return false
	}
	hash, err := final.Hash()
	if err != nil {
		log.Error(err.Error())
		return false
	}
	if !bytes.Equal(hash, Msg) {
		log.Error("hash of received Final stmt and msg are not equal")
		return false
	}
	var fs *FinalStatement
	var ok bool

	if fs, ok = s.data.Finals[string(final.Desc.Hash())]; !ok {
		log.Error("final Statement not found")
		return false
	}

	hash, err = fs.Hash()

	if !bytes.Equal(hash, Msg) {
		log.Error("hash of lccocal Final stmt and msg are not equal")
		return false
	}
	return true
}

//signs FinalStatement with BFTCosi and Propagates signature to other nodes
func (s *Service) signAndPropagateFinal(final *FinalStatement) onet.ClientError {
	tree := final.Desc.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return onet.NewClientErrorCode(ErrorInternal,
			"Root does not exist")
	}
	node, err := s.CreateProtocol(bftSignMerge, tree)
	if err != nil {
		return onet.NewClientError(err)
	}

	// Register the function generating the protocol instance
	root, ok := node.(*bftcosi.ProtocolBFTCoSi)
	if !ok {
		return onet.NewClientErrorCode(ErrorInternal,
			"protocol instance is invalid")
	}

	root.Msg, err = final.Hash()
	if err != nil {
		return onet.NewClientError(err)
	}

	root.Data, err = final.ToToml()
	if err != nil {
		return onet.NewClientError(err)
	}

	final.Signature = []byte{}
	signature := make(chan []byte)
	root.RegisterOnSignatureDone(func(sig *bftcosi.BFTSignature) {
		if len(sig.Sig) >= 64 {
			signature <- sig.Sig[:64]
		} else {
			signature <- []byte{}
		}
	})

	go node.Start()

	select {
	case final.Signature, ok = <-signature:
		break
	case <-time.After(TIMEOUT):
		log.Error("signing failed on timeout")
		return onet.NewClientErrorCode(ErrorTimeout,
			"signing timeout")
	}

	replies, err := s.Propagate(final.Desc.Roster, final, 10000)
	if err != nil {
		return onet.NewClientError(err)
	}
	if replies != len(final.Desc.Roster.List) {
		log.Warn("Did only get", replies)
	}
	s.save()
	return nil
}

// PropagateFinal saves the new final statement
func (s *Service) PropagateFinal(msg network.Message) {
	fs, ok := msg.(*FinalStatement)
	if !ok {
		log.Error("Couldn't convert to a FinalStatement")
		return
	}
	if err := fs.Verify(); err != nil {
		log.Error(err)
		return
	}
	*s.data.Finals[string(fs.Desc.Hash())] = *fs
	s.save()
	log.Lvlf2("%s Stored final statement %v", s.ServerIdentity(), fs)
}

// FetchFinal returns FinalStatement by hash
// used after Finalization
func (s *Service) FetchFinal(req *FetchRequest) (network.Message,
	onet.ClientError) {
	log.Lvlf2("FetchFinal: %s %v", s.Context.ServerIdentity(), req.ID)
	var fs *FinalStatement
	var ok bool
	if fs, ok = s.data.Finals[string(req.ID)]; !ok {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"No config found")
	}
	if len(fs.Signature) <= 0 {
		return nil, onet.NewClientErrorCode(ErrorOtherFinals,
			"Not all other conodes finalized yet")
	}
	return &FinalizeResponse{fs}, nil
}

// MergeRequest starts Merge process and returns FinalStatement after
// used after finalization
func (s *Service) MergeRequest(req *MergeRequest) (network.Message,
	onet.ClientError) {
	log.Lvlf2("MergeRequest: %s %v", s.Context.ServerIdentity(), req.ID)
	if s.data.Public == nil {
		return nil, onet.NewClientErrorCode(ErrorInternal, "Not linked yet")
	}

	if err := crypto.VerifySchnorr(network.Suite, s.data.Public, req.ID, req.Signature); err != nil {
		return nil, onet.NewClientErrorCode(ErrorInternal, "Invalid signature: err")
	}

	var final *FinalStatement
	var meta *mergeMeta
	var ok bool
	if final, ok = s.data.Finals[string(req.ID)]; !ok {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"No config found")
	}
	if meta, ok = s.data.mergeMetas[string(req.ID)]; !ok {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"No meta found")
	}

	if len(final.Signature) <= 0 || final.Verify() != nil {
		return nil, onet.NewClientErrorCode(ErrorOtherFinals,
			"Not all other conodes finalized yet")
	}
	if len(final.Desc.Parties) <= 1 {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"Party is unmergeable")
	}
	if final.Merged {
		return &FinalizeResponse{final}, nil
	}
	// Check if the party is the merge list
	found := false
	for _, party := range final.Desc.Parties {
		if Equal(party.Roster, final.Desc.Roster) {
			found = true
			break
		}
	}
	if !found {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"Party is not included in merge list")
	}
	err := s.Merge(final, meta)
	if err != nil {
		return nil, err
	}
	err = s.signAndPropagateFinal(final)
	if err != nil {
		return nil, err
	}
	// trigger merging process
	return &FinalizeResponse{final}, nil
}

// MergeConfig receives a final statement of requesting party,
// hash of local party. Checks if they are from one merge party and responses with
// own finalStatement
func (s *Service) MergeConfig(req *network.Envelope) {
	log.Lvlf2("%s gets MergeConfig from %s", s.Context.ServerIdentity().String(),
		req.ServerIdentity.String())
	mc, ok := req.Msg.(*MergeConfig)
	if !ok {
		log.Errorf("Didn't get a MergeConfig: %#v", req.Msg)
		return
	}
	if mc.Final == nil || mc.Final.Desc == nil {
		log.Error("MergeConfig is empty")
		return
	}
	mcr := &MergeConfigReply{PopStatusOK, mc.Final.Desc.Hash(), nil}

	var final *FinalStatement
	var meta *mergeMeta
	if final, ok = s.data.Finals[string(mc.ID)]; !ok {
		log.Errorf("No config found")
		mcr.PopStatus = PopStatusWrongHash
		goto send
	}
	if meta, ok = s.data.mergeMetas[string(mc.ID)]; !ok {
		log.Error("No merge set found")
		mcr.PopStatus = PopStatusWrongHash
		goto send
	}

	mcr.PopStatus = final.VerifyMergeStatement(mc.Final)
	if mcr.PopStatus < PopStatusOK {
		goto send
	}
	if _, ok = meta.statementsMap[string(mc.Final.Desc.Hash())]; ok {
		log.Lvl2(s.ServerIdentity(), "Party was already merged, sent from",
			req.ServerIdentity.String())
		mcr.PopStatus = PopStatusMergeError
		goto send
	} else {
		meta.statementsMap[string(mc.Final.Desc.Hash())] = mc.Final
	}

	mcr.Final = final

send:
	err := s.SendRaw(req.ServerIdentity, mcr)
	if err != nil {
		log.Error("Couldn't send reply:", err)
	}
}

// MergeConfigReply processes the response after MergeConfig message
func (s Service) MergeConfigReply(req *network.Envelope) {
	log.Lvlf2("MergeConfigReply: %s from %s got %v",
		s.ServerIdentity(), req.ServerIdentity.String(), req.Msg)
	mcrVal, ok := req.Msg.(*MergeConfigReply)
	var mcr *MergeConfigReply
	mcr = func() *MergeConfigReply {
		if !ok {
			log.Errorf("Didn't get a CheckConfigReply: %v", req.Msg)
			return nil
		}
		var final *FinalStatement
		if final, ok = s.data.Finals[string(mcrVal.PopHash)]; !ok {
			log.Error("No party with given hash")
			return nil
		}
		if mcrVal.PopStatus < PopStatusOK {
			log.Error("Wrong pop-status:", mcrVal.PopStatus)
			return mcrVal
		}
		if mcrVal.Final == nil {
			log.Error("Empty FinalStatement in reply")
			return nil
		}
		mcrVal.PopStatus = final.VerifyMergeStatement(mcrVal.Final)
		return mcrVal
	}()
	if syncData, ok := s.data.syncMetas[string(mcrVal.PopHash)]; ok {
		if len(syncData.mcChannel) == 0 {
			syncData.mcChannel <- mcr
		}
	} else {
		log.Error("No hash for syncMeta found")
	}
}

// CheckConfig receives a hash for a config and a list of attendees. It returns
// a CheckConfigReply filled according to this structure's description. If
// the config has been found, it strips its own attendees from the one missing
// in the other configuration.
func (s *Service) CheckConfig(req *network.Envelope) {
	cc, ok := req.Msg.(*CheckConfig)
	if !ok {
		log.Errorf("Didn't get a CheckConfig: %#v", req.Msg)
		return
	}

	ccr := &CheckConfigReply{PopStatusOK, cc.PopHash, nil}
	if len(s.data.Finals) > 0 {
		var final *FinalStatement
		if final, ok = s.data.Finals[string(cc.PopHash)]; !ok {
			ccr.PopStatus = PopStatusWrongHash
		} else {
			final.Attendees = intersectAttendees(final.Attendees, cc.Attendees)
			if len(final.Attendees) == 0 {
				ccr.PopStatus = PopStatusNoAttendees
			} else {
				ccr.PopStatus = PopStatusOK
				ccr.Attendees = final.Attendees
			}
		}
	}
	log.Lvl2(s.Context.ServerIdentity(), ccr.PopStatus, ccr.Attendees)
	err := s.SendRaw(req.ServerIdentity, ccr)
	if err != nil {
		log.Error("Couldn't send reply:", err)
	}
}

// CheckConfigReply strips the attendees missing in the reply, if the
// PopStatus == PopStatusOK.
func (s *Service) CheckConfigReply(req *network.Envelope) {
	ccrVal, ok := req.Msg.(*CheckConfigReply)
	var ccr *CheckConfigReply
	ccr = func() *CheckConfigReply {
		if !ok {
			log.Errorf("Didn't get a CheckConfigReply: %v", req.Msg)
			return nil
		}
		var final *FinalStatement
		if final, ok = s.data.Finals[string(ccrVal.PopHash)]; !ok {
			log.Error("No party with given hash")
			return nil
		}
		if ccrVal.PopStatus < PopStatusOK {
			log.Error("Wrong pop-status:", ccrVal.PopStatus)
			return nil
		}
		final.Attendees = intersectAttendees(final.Attendees, ccrVal.Attendees)
		return ccrVal
	}()
	if syncData, ok := s.data.syncMetas[string(ccrVal.PopHash)]; ok {
		if len(syncData.ccChannel) == 0 {
			syncData.ccChannel <- ccr
		}
	} else {
		log.Error("No hash for syncMeta found")
	}
}

// MergeCheck propagates the finalStatement among the fellows of one party
func (s *Service) MergeCheck(req *network.Envelope) {
	msg, ok := req.Msg.(*MergeCheck)
	log.Lvlf2("%s recieved MergeCheck from %s", s.ServerIdentity(), req.ServerIdentity.String())
	if !ok {
		log.Errorf("Didn't get a MergeCheck: %v", req.Msg)
		return
	}
	mcr := &MergeCheckReply{msg.IDsndr, PopStatusOK}
	found := false
	var hash []byte
	var err error
	var final *FinalStatement
	var meta *mergeMeta
	var syncData *syncMeta

	var newHash string
	locs := make([]string, 0)
	if final, ok = s.data.Finals[string(msg.IDrecv)]; !ok {
		log.Error("No party with given hash")
		mcr.PopStatus = PopStatusWrongHash
		goto send
	}

	if meta, ok = s.data.mergeMetas[string(msg.IDrecv)]; !ok {
		log.Error("No party with given hash")
		mcr.PopStatus = PopStatusWrongHash
		goto send
	}

	if syncData, ok = s.data.syncMetas[string(msg.IDrecv)]; !ok {
		log.Error("No party with given hash")
		mcr.PopStatus = PopStatusWrongHash
		goto send
	}

	hash, err = final.Hash()
	if err != nil {
		log.Error(err)
		mcr.PopStatus = PopStatusMergeError
		goto send
	}

	for _, mergeStmt := range msg.MergeInfo {
		hashMerge, err := mergeStmt.Hash()
		if err != nil {
			log.Error(err)
			mcr.PopStatus = PopStatusMergeError
			goto send
		}
		if bytes.Equal(hash, hashMerge) {
			found = true
		}
		status := final.VerifyMergeStatement(&mergeStmt)
		if status < PopStatusOK {
			log.Error("Received non valid FinalStatement")
			mcr.PopStatus = PopStatusMergeError
			goto send
		}
	}
	if !found {
		log.Error("The local party is not included in Merge List of recieved")
		mcr.PopStatus = PopStatusMergeError
		goto send
	}
	final.Desc.Location = ""
	for _, f := range msg.MergeInfo {
		final.Attendees = unionAttendies(final.Attendees, f.Attendees)
		final.Desc.Roster = unionRoster(final.Desc.Roster, f.Desc.Roster)
		locs = append(locs, f.Desc.Location)
	}
	sort.Slice(locs, func(i, j int) bool {
		return strings.Compare(locs[i], locs[j]) < 0
	})
	final.Desc.Location = strings.Join(locs, DELIMETER)
	final.Merged = true

	newHash = string(final.Desc.Hash())
	s.data.Finals[newHash] = final
	s.data.mergeMetas[newHash] = meta
	s.data.syncMetas[newHash] = syncData
	meta.statementsMap = make(map[string]*FinalStatement)
	meta.statementsMap[newHash] = final

	s.save()
send:
	s.SendRaw(req.ServerIdentity, mcr)
}

func (s *Service) MergeCheckReply(req *network.Envelope) {
	log.Lvlf2("%s recieved MergeCheckReply %+v from %s", s.ServerIdentity(), req.Msg, req.ServerIdentity.String())
	msg, ok := req.Msg.(*MergeCheckReply)
	if !ok {
		log.Errorf("Didn't get a MergeCheckReply: %v", req.Msg)
	}
	if msg.PopStatus < PopStatusOK {
		log.Error("Wrong pop status on MergeCheckReply", msg.PopStatus)
	}
	if syncData, ok := s.data.syncMetas[string(msg.ID)]; ok {
		syncData.mcGroup.Done()
	} else {
		log.Error("No hash found on MergeCheckReply")
	}
}

func (s *Service) broadcastFinal(final *FinalStatement, meta *mergeMeta) error {
	msg := &MergeCheck{}
	msg.MergeInfo = make([]FinalStatement, len(meta.statementsMap))
	i := 0
	for _, f := range meta.statementsMap {
		msg.MergeInfo[i] = *f
		i++
	}
	msg.IDsndr = final.Desc.Hash()

	syncData, ok := s.data.syncMetas[string(final.Desc.Hash())]
	if !ok {
		return errors.New("Sync Data not found by hash")
	}

	// Count number of conodes except current
	n := 0
	for _, p := range final.Desc.Parties {
		n += len(p.Roster.List)
	}
	n--
	syncData.mcGroup.Add(n)

	var pop PopDesc
	for _, party := range final.Desc.Parties {
		pop.Name = final.Desc.Name
		pop.DateTime = final.Desc.DateTime
		pop.Parties = final.Desc.Parties
		pop.Location = party.Location
		pop.Roster = party.Roster
		msg.IDrecv = pop.Hash()

		for _, si := range party.Roster.List {
			if !(s.ServerIdentity().Equal(si) &&
				bytes.Equal(msg.IDrecv, final.Desc.Hash())) {
				err := s.SendRaw(si, msg)
				if err != nil {
					return err
				}
			}
		}
	}
	syncData.mcGroup.Wait()
	return nil
}

// Merge sends MergeConfig to all parties,
// Receives Replies, updates info about global merge party
// When all merge party's info is saved, merge it and starts global sighning process
// After all, sends StoreConfig request to other conodes of own party
func (s *Service) Merge(final *FinalStatement, meta *mergeMeta) onet.ClientError {
	if meta.distrib {
		// Used not to start merge process 2 times, when one is on run.
		log.Lvl2(s.ServerIdentity(), "Not enter merge")
		return nil
	}
	log.Lvl2("Merge ", s.ServerIdentity())
	meta.distrib = true
	// Flag indicating that there were connection with other nodes
	syncData, ok := s.data.syncMetas[string(final.Desc.Hash())]
	if !ok {
		return onet.NewClientErrorCode(ErrorMerge, "Wrong Hash")
	}
	for _, party := range final.Desc.Parties {
		popDesc := PopDesc{
			Name:     final.Desc.Name,
			DateTime: final.Desc.DateTime,
			Location: party.Location,
			Roster:   party.Roster,
			Parties:  final.Desc.Parties,
		}
		hash := popDesc.Hash()
		if _, ok := meta.statementsMap[string(hash)]; ok {
			// that's unlikely due to running in cycle
			continue
		}
		mc := &MergeConfig{Final: final, ID: hash}
		for _, si := range party.Roster.List {
			log.Lvlf2("Sending from %s to %s", s.ServerIdentity(), si)
			err := s.SendRaw(si, mc)
			if err != nil {
				return onet.NewClientErrorCode(ErrorInternal, err.Error())
			}
			var mcr *MergeConfigReply
			select {
			case mcr = <-syncData.mcChannel:
				break
			case <-time.After(TIMEOUT):
				return onet.NewClientErrorCode(ErrorTimeout,
					"timeout on waiting response MergeConfig")
			}
			if mcr == nil {
				return onet.NewClientErrorCode(ErrorMerge,
					"Error during merging")
			}
			if mcr.PopStatus == PopStatusOK {
				meta.statementsMap[string(hash)] = mcr.Final
				break
			}
		}
		if _, ok = meta.statementsMap[string(hash)]; !ok {
			return onet.NewClientErrorCode(ErrorMerge,
				"merge with party failed")
		}
	}
	// send merge info to fellows from the same party
	err := s.broadcastFinal(final, meta)
	if err != nil {
		return onet.NewClientError(err)
	}

	// Unite the lists
	locs := make([]string, 0)
	Roster := &onet.Roster{}
	for _, f := range meta.statementsMap {
		// although there must not be any intersection
		// in attendies list it's better to check it
		// not simply extend the list
		final.Attendees = unionAttendies(final.Attendees, f.Attendees)
		Roster = unionRoster(Roster, f.Desc.Roster)
		locs = append(locs, f.Desc.Location)
	}
	sort.Slice(locs, func(i, j int) bool {
		return strings.Compare(locs[i], locs[j]) < 0
	})
	final.Desc.Location = strings.Join(locs, DELIMETER)
	final.Desc.Roster = Roster
	final.Merged = true

	// refresh data
	hash := string(final.Desc.Hash())
	s.data.Finals[hash] = final
	s.data.mergeMetas[hash] = meta
	s.data.syncMetas[hash] = syncData
	meta.statementsMap = make(map[string]*FinalStatement)
	meta.statementsMap[hash] = final
	return nil
}

// function used in bft
func (s *Service) bftVerifyMerge(Msg []byte, Data []byte) bool {
	fs, err := NewFinalStatementFromToml(Data)
	if err != nil {
		log.Error(err.Error())
		return false
	}
	hashReceived, err := fs.Hash()
	if err != nil {
		log.Error(err.Error())
		return false
	}
	if !bytes.Equal(Msg, hashReceived) {
		log.Error("Msg to sign differs from data hash")
		return false
	}

	// searching for local party
	hash := fs.Desc.Hash()
	var localFinal *FinalStatement
	var ok bool
	if localFinal, ok = s.data.Finals[string(hash)]; !ok {
		log.Error("No party is here")
		log.Fatal("oh no")
		return false
	}

	hashLocal, err := localFinal.Hash()

	if err != nil {
		log.Error(err.Error())
		return false
	}

	if !bytes.Equal(hashLocal, hashReceived) {
		log.Error("hashes of local and sent finalStatements are not equal")
		return false
	}
	return true
}

// VerifyMergeStatement checks that received mergeFinal is valid and can be merged with final
func (final *FinalStatement) VerifyMergeStatement(mergeFinal *FinalStatement) int {
	if final.Verify() != nil {
		log.Error("Local party's signature is invalid")
	}
	if len(mergeFinal.Signature) <= 0 {
		log.Error("Received party is not finished")
		return PopStatusMergeNonFinalized
	}
	if mergeFinal.Verify() != nil {
		log.Error("Received config party signature is invalid")
		return PopStatusMergeError
	}

	if final.Desc.DateTime != mergeFinal.Desc.DateTime {
		log.Error("Parties were held in different times")
		return PopStatusMergeError
	}

	// Check if the party is the merge list
	found := true
	for _, party := range final.Desc.Parties {
		if Equal(party.Roster, mergeFinal.Desc.Roster) {
			found = true
			break
		}
	}
	if !found {
		log.Error("Party is not included in merge list")
		return PopStatusMergeError
	}

	return PopStatusOK
}

// Get intersection of attendees
func intersectAttendees(atts1, atts2 []abstract.Point) []abstract.Point {
	myMap := make(map[string]bool)

	for _, p := range atts1 {
		myMap[p.String()] = true
	}
	min := len(atts1)
	if min < len(atts1) {
		min = len(atts1)
	}
	na := make([]abstract.Point, 0, min)
	for _, p := range atts2 {
		if _, ok := myMap[p.String()]; ok {
			na = append(na, p)
		}
	}
	return na
}

func unionAttendies(atts1, atts2 []abstract.Point) []abstract.Point {
	myMap := make(map[string]bool)
	na := make([]abstract.Point, 0, len(atts1)+len(atts2))

	na = append(na, atts1...)
	for _, p := range atts1 {
		myMap[p.String()] = true
	}

	for _, p := range atts2 {
		if _, ok := myMap[p.String()]; !ok {
			na = append(na, p)
		}
	}
	sort.Slice(na, func(i, j int) bool {
		return strings.Compare(na[i].String(), na[j].String()) < 0
	})
	return na
}

func unionRoster(r1, r2 *onet.Roster) *onet.Roster {
	myMap := make(map[string]bool)
	na := make([]*network.ServerIdentity, 0, len(r1.List)+len(r2.List))

	na = append(na, r1.List...)
	for _, s := range r1.List {
		myMap[s.String()] = true
	}
	for _, s := range r2.List {
		if _, ok := myMap[s.String()]; !ok {
			na = append(na, s)
		}
	}
	sort.Slice(na, func(i, j int) bool {
		return strings.Compare(na[i].String(), na[j].String()) < 0
	})
	return onet.NewRoster(na)
}

// saves the actual identity
func (s *Service) save() {
	log.Lvl2("Saving service", s.ServerIdentity())
	err := s.Save("storage", s.data)
	if err != nil {
		log.Error("Couldn't save data:", err)
	}
}

// Tries to load the configuration and updates if a configuration
// is found, else it returns an error.
func (s *Service) tryLoad() error {
	if !s.DataAvailable("storage") {
		return nil
	}
	msg, err := s.Load("storage")
	if err != nil {
		return err
	}
	var ok bool
	s.data, ok = msg.(*saveData)
	if !ok {
		return errors.New("Data of wrong type")
	}
	return nil
}

// newService registers the request-methods.
func newService(c *onet.Context) onet.Service {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		data:             &saveData{},
	}
	log.ErrFatal(s.RegisterHandlers(s.PinRequest, s.StoreConfig, s.FinalizeRequest,
		s.FetchFinal, s.MergeRequest), "Couldn't register messages")
	if err := s.tryLoad(); err != nil {
		log.Error(err)
	}
	if s.data.Finals == nil {
		s.data.Finals = make(map[string]*FinalStatement)
	}
	if s.data.mergeMetas == nil {
		s.data.mergeMetas = make(map[string]*mergeMeta)
	}
	if s.data.syncMetas == nil {
		s.data.syncMetas = make(map[string]*syncMeta)
	}
	var err error
	s.Propagate, err = messaging.NewPropagationFunc(c, "PoPPropagate", s.PropagateFinal)
	log.ErrFatal(err)
	s.RegisterProcessorFunc(checkConfigID, s.CheckConfig)
	s.RegisterProcessorFunc(checkConfigReplyID, s.CheckConfigReply)
	s.RegisterProcessorFunc(mergeConfigID, s.MergeConfig)
	s.RegisterProcessorFunc(mergeConfigReplyID, s.MergeConfigReply)
	s.RegisterProcessorFunc(mergeCheckID, s.MergeCheck)
	s.RegisterProcessorFunc(mergeCheckReplyID, s.MergeCheckReply)
	s.ProtocolRegister(bftSignFinal, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return bftcosi.NewBFTCoSiProtocol(n, s.bftVerifyFinal)
	})
	s.ProtocolRegister(bftSignMerge, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return bftcosi.NewBFTCoSiProtocol(n, s.bftVerifyMerge)
	})
	return s
}
