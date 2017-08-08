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

	"gopkg.in/dedis/cothority.v1/cosi/protocol"
	"gopkg.in/dedis/cothority.v1/messaging"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

// Name is the name to refer to the Template service from another
// package.
const Name = "PoPServer"
const cfgName = "pop.bin"
const protoCoSi = "CoSiFinal"

var checkConfigID network.MessageTypeID
var checkConfigReplyID network.MessageTypeID
var mergeConfigID network.MessageTypeID
var mergeConfigReplyID network.MessageTypeID
var mergeCheckID network.MessageTypeID

func init() {
	onet.RegisterNewService(Name, newService)
	network.RegisterMessage(&saveData{})
	checkConfigID = network.RegisterMessage(CheckConfig{})
	checkConfigReplyID = network.RegisterMessage(CheckConfigReply{})
	mergeConfigID = network.RegisterMessage(MergeConfig{})
	mergeConfigReplyID = network.RegisterMessage(MergeConfigReply{})
	mergeCheckID = network.RegisterMessage(MergeCheck{})
}

// Service represents data needed for one pop-party.
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	path string
	data *saveData
	// channel to return the configreply
	ccChannel chan *CheckConfigReply
	// channel to return the mergereply
	mcChannel chan *MergeConfigReply
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
	MergeMetas map[string]*MergeMeta
}

type MergeMeta struct {
	// Map of final statements of parties that are going to be merged together
	statementsMap map[string]*FinalStatement
	// Flag tells that message distribution has already started
	distrib bool
}

func newMergeMeta() *MergeMeta {
	mm := &MergeMeta{}
	mm.statementsMap = make(map[string]*FinalStatement)
	mm.distrib = false
	return mm
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
	s.data.Finals[string(hash)] = &FinalStatement{Desc: req.Desc, Signature: []byte{}}
	if len(req.Desc.Parties) > 0 {
		mergeMeta := newMergeMeta()
		s.data.MergeMetas[string(hash)] = mergeMeta
		// party is merged with itself already
		mergeMeta.statementsMap[string(hash)] = s.data.Finals[string(hash)]
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
			rep := <-s.ccChannel
			if rep == nil {
				return nil, onet.NewClientErrorCode(ErrorOtherFinals,
					"Not all other conodes finalized yet")
			}
		}
	}

	// Create final signature
	tree := final.Desc.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"Root does not exist")
	}
	node, err := s.CreateProtocol(cosi.Name, tree)
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	signature := make(chan []byte)
	c := node.(*cosi.CoSi)
	c.RegisterSignatureHook(func(sig []byte) {
		signature <- sig[:64]
	})
	c.Message, err = final.Hash()
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	go node.Start()

	final.Signature = <-signature
	replies, err := s.Propagate(final.Desc.Roster, final, 10000)
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	if replies != len(final.Desc.Roster.List) {
		log.Warn("Did only get", replies)
	}
	return &FinalizeResponse{final}, nil
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
	s.data.Finals[string(fs.Desc.Hash())] = fs
	s.save()
	log.Lvlf2("%s Stored final statement %v", s.ServerIdentity(), fs)
}

// FetchFinal returns FinalStatement by hash
// used after Finalization
func (s *Service) FetchFinal(req *FetchRequest) (network.Message,
	onet.ClientError) {
	log.Lvlf2("FetchFinal: %s %v", s.Context.ServerIdentity(), req.ID)
	if fs, ok := s.data.Finals[string(req.ID)]; !ok {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"No config found")
	} else {
		if len(fs.Signature) <= 0 {
			return nil, onet.NewClientErrorCode(ErrorOtherFinals,
				"Not all other conodes finalized yet")
		} else {
			return &FinalizeResponse{fs}, nil
		}
	}
}

func (s *Service) MergeRequest(req *MergeRequest) (network.Message,
	onet.ClientError) {
	log.Lvlf2("MergeRequest: %s %v", s.Context.ServerIdentity(), req.ID)
	var final *FinalStatement
	var mergeMeta *MergeMeta
	var ok bool
	if final, ok = s.data.Finals[string(req.ID)]; !ok {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"No config found")
	}
	if mergeMeta, ok = s.data.MergeMetas[string(req.ID)]; !ok {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"No mergeMeta found")
	}
	if len(final.Signature) <= 0 || final.Verify() != nil {
		return nil, onet.NewClientErrorCode(ErrorOtherFinals,
			"Not all other conodes finalized yet")
	}
	if len(final.Desc.Parties) <= 1 {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"Party is unmergeable")
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
	// trigger merging process
	return s.Merge(final, mergeMeta)
}

// MergeConfig recieves a final statement of requesting party,
// hash of local party. And tries to merge them
func (s *Service) MergeConfig(req *network.Envelope) {
	log.Lvlf2("%s gets MergeConfig from %s", s.Context.ServerIdentity().String(),
		req.ServerIdentity.String())
	// predeclaration due to use of goto
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
	var mergeMeta *MergeMeta
	if final, ok = s.data.Finals[string(mc.ID)]; !ok {
		log.Errorf("No config found")
		mcr.PopStatus = PopStatusWrongHash
		goto send
	}
	if mergeMeta, ok = s.data.MergeMetas[string(mc.ID)]; !ok {
		log.Error("No merge set found")
		mcr.PopStatus = PopStatusWrongHash
		goto send
	}
	mcr.PopStatus = final.VerifyMergeStatement(mc.Final)
	if mcr.PopStatus < PopStatusOK {
		goto send
	}
	if _, ok = mergeMeta.statementsMap[string(mc.Final.Desc.Hash())]; ok {
		log.Lvl2(s.ServerIdentity(), "Party was already merged, sent from",
			req.ServerIdentity.String())
		mcr.PopStatus = PopStatusMergeError
		goto send
	} else {
		mergeMeta.statementsMap[string(mc.Final.Desc.Hash())] = mc.Final
	}

	mcr.Final = final

send:
	// send reply
	err := s.SendRaw(req.ServerIdentity, mcr)
	if err != nil {
		log.Error("Couldn't send reply:", err)
	}
	if mcr.PopStatus < PopStatusOK {
		return
	}
	// send merge info to other parties nodes
	_, err = s.Merge(final, mergeMeta)
	if err != nil {
		log.Errorf("%s Merge error %s", s.ServerIdentity(), err.Error())
	}
}

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
	if len(s.mcChannel) == 0 {
		s.mcChannel <- mcr
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

	ccr := &CheckConfigReply{0, cc.PopHash, nil}
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
	if len(s.ccChannel) == 0 {
		s.ccChannel <- ccr
	}
}

func (s *Service) MergeCheck(req *network.Envelope) {
	msg, ok := req.Msg.(*MergeCheck)
	log.Lvlf2("%s recieved MergeCheck %+v from %s", s.ServerIdentity(), msg, req.ServerIdentity.String())
	if !ok {
		log.Errorf("Didn't get a MergeCheck: %v", req.Msg)
		return
	}

	var final *FinalStatement
	if final, ok = s.data.Finals[string(msg.ID)]; !ok {
		log.Error("No party with given hash")
		return
	}

	for _, mergeStmt := range msg.MergeInfo {
		if mergeStmt.Desc.Location == final.Desc.Location {
			continue
		}
		status := final.VerifyMergeStatement(&mergeStmt)
		if status < PopStatusOK {
			log.Error("Recieved non valid FinalStatement")
			return
		}
	}
	for _, f := range msg.MergeInfo {
		final.Attendees = unionAttendies(final.Attendees, f.Attendees)
		final.Desc.Roster = unionRoster(final.Desc.Roster, f.Desc.Roster)
	}

	// Create Signature
	tree := final.Desc.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		log.Error("Root does not exist")
		return
	}

	node, err := s.CreateProtocol(cosi.Name, tree)
	if err != nil {
		log.Error(err.Error())
		return
	}
	signature := make(chan []byte)
	c := node.(*cosi.CoSi)

	c.RegisterSignatureHook(func(sig []byte) {
		signature <- sig[:64]
	})
	c.Message, err = final.Hash()
	if err != nil {
		log.Error(err.Error())
		return
	}
	go node.Start()

	final.Signature = <-signature
	final.Merged = true

	s.save()
}

func (s *Service) sendToPartyFellows(final *FinalStatement, mergeMeta *MergeMeta) error {
	msg := &MergeCheck{final.Desc.Hash(), []FinalStatement{}}
	msg.MergeInfo = make([]FinalStatement, len(mergeMeta.statementsMap))
	i := 0
	for _, f := range mergeMeta.statementsMap {
		msg.MergeInfo[i] = *f
		i++
	}
	for _, si := range final.Desc.Roster.List {
		if !s.ServerIdentity().Equal(si) {
			err := s.SendRaw(si, msg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Sends MergeConfig to all parties,
// Receives Replies, updates info about global merge party
// When all merge party's info is saved, merge it and starts global sighning process
// After all, sends StoreConfig request to other conodes of own party
func (s *Service) Merge(final *FinalStatement, mergeMeta *MergeMeta) (*FinalizeResponse, onet.ClientError) {
	if mergeMeta.distrib {
		log.Lvl2(s.ServerIdentity(), "Not enter merge")
		return &FinalizeResponse{final}, nil
	}
	log.Lvl2("Merge ", s.ServerIdentity())
	mergeMeta.distrib = true
	// Flag indicating that there were connection with other nodes
	for _, party := range final.Desc.Parties {
		popDesc := PopDesc{
			Name:     final.Desc.Name,
			DateTime: final.Desc.DateTime,
			Location: party.Location,
			Roster:   party.Roster,
			Parties:  final.Desc.Parties,
		}
		hash := popDesc.Hash()
		if _, ok := mergeMeta.statementsMap[string(hash)]; ok {
			continue
		}
		mc := &MergeConfig{Final: final, ID: hash}
		for _, si := range party.Roster.List {
			log.Lvlf2("Sending from %s to %s", s.ServerIdentity(), si)
			err := s.SendRaw(si, mc)
			if err != nil {
				return nil, onet.NewClientErrorCode(ErrorInternal, err.Error())
			}
			mcr := <-s.mcChannel
			if mcr == nil {
				return nil, onet.NewClientErrorCode(ErrorMerge,
					"Error during merging")
			}
			if mcr.PopStatus == PopStatusOK {
				mergeMeta.statementsMap[string(mcr.Final.Desc.Hash())] = mcr.Final
				break
			}
		}
	}
	// send merge info to fellows from the same party
	err := s.sendToPartyFellows(final, mergeMeta)
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	final.Signature = []byte{}
	// Unite the lists
	for _, f := range mergeMeta.statementsMap {
		// although there must not be any intersection
		// in attendies list it's better to check it
		// not simply extend the list
		final.Attendees = unionAttendies(final.Attendees, f.Attendees)
		final.Desc.Roster = unionRoster(final.Desc.Roster, f.Desc.Roster)
	}
	sort.Slice(final.Attendees, func(i, j int) bool {
		return strings.Compare(final.Attendees[i].String(), final.Attendees[j].String()) < 0
	})
	tree := final.Desc.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, onet.NewClientErrorCode(ErrorInternal,
			"Root does not exist")
	}
	node, err := s.CreateProtocol(cosi.Name, tree)
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	signature := make(chan []byte)
	c := node.(*cosi.CoSi)

	c.RegisterSignatureHook(func(sig []byte) {
		signature <- sig[:64]
	})
	c.Message, err = final.Hash()
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	go node.Start()

	final.Signature = <-signature
	final.Merged = true
	s.save()
	return &FinalizeResponse{final}, nil
}

// Checks that received mergeFinal is valid and can be merged with final
func (final *FinalStatement) VerifyMergeStatement(mergeFinal *FinalStatement) int {
	if len(final.Signature) <= 0 || final.Verify() != nil {
		log.Error("Not all other conodes finalized yet")
		return PopStatusMergeNonFinalized
	}
	if len(final.Desc.Parties) <= 0 {
		log.Error("Party is unmergeable")
		return PopStatusMergeError
	}
	if final.Desc.DateTime != mergeFinal.Desc.DateTime {
		log.Error("Parties were held in different times")
		return PopStatusMergeError
	}

	if len(mergeFinal.Signature) <= 0 {
		log.Error("Received config is from unfinished party")
		return PopStatusMergeError
	}
	hash, err := final.Hash()
	if err != nil {
		log.Error(err)
		return PopStatusMergeError
	}
	hashMerge, err := mergeFinal.Hash()
	if err != nil {
		log.Error(err)
		return PopStatusMergeError
	}
	if Equal(final.Desc.Roster, mergeFinal.Desc.Roster) ||
		bytes.Equal(hash, hashMerge) {
		log.Error("The same party")
		return PopStatusMergeError
	}
	// Check if the party is the merge list
	found := 0
	for _, party := range final.Desc.Parties {
		if Equal(party.Roster, final.Desc.Roster) {
			found++
			if found == 2 {
				break
			}
		}
		if Equal(party.Roster, mergeFinal.Desc.Roster) {
			found++
			if found == 2 {
				break
			}
		}
	}
	if found < 2 {
		log.Error("One of parties or both are not included in merge list")
		return PopStatusMergeError
	}
	if mergeFinal == nil || mergeFinal.Verify() != nil {
		log.Error("Recieved config party signature is not valid")
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
		ccChannel:        make(chan *CheckConfigReply, 1),
		mcChannel:        make(chan *MergeConfigReply, 1),
	}
	log.ErrFatal(s.RegisterHandlers(s.PinRequest, s.StoreConfig, s.FinalizeRequest,
		s.FetchFinal, s.MergeRequest), "Couldn't register messages")
	if err := s.tryLoad(); err != nil {
		log.Error(err)
	}
	if s.data.Finals == nil {
		s.data.Finals = make(map[string]*FinalStatement)
	}
	if s.data.MergeMetas == nil {
		s.data.MergeMetas = make(map[string]*MergeMeta)
	}
	var err error
	s.Propagate, err = messaging.NewPropagationFunc(c, "PoPPropagate", s.PropagateFinal)
	log.ErrFatal(err)
	s.RegisterProcessorFunc(checkConfigID, s.CheckConfig)
	s.RegisterProcessorFunc(checkConfigReplyID, s.CheckConfigReply)
	s.RegisterProcessorFunc(mergeConfigID, s.MergeConfig)
	s.RegisterProcessorFunc(mergeConfigReplyID, s.MergeConfigReply)
	s.RegisterProcessorFunc(mergeCheckID, s.MergeCheck)
	return s
}
