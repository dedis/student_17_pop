package service

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/network"
)

// We need to register all messages so the network knows how to handle them.
func init() {
	for _, msg := range []interface{}{
		CheckConfig{}, CheckConfigReply{},
		PinRequest{}, FetchRequest{}, MergeRequest{},
	} {
		network.RegisterMessage(msg)
	}
}

const (
	// PopStatusWrongHash - The different configs in the roster don't have the same hash
	PopStatusWrongHash = iota
	// PopStatusNoAttendees - No common attendees found
	PopStatusNoAttendees
	// PopStatusMergeError - Error in merge config
	PopStatusMergeError
	// PopStatusMergeNonFinalized - Attempt to merge not finalized party
	PopStatusMergeNonFinalized
	// PopStatusOK - Everything is OK
	PopStatusOK
)

// CheckConfig asks whether the pop-config and the attendees are available.
type CheckConfig struct {
	PopHash   []byte
	Attendees []abstract.Point
}

// CheckConfigReply sends back an integer for the Pop. 0 means no config yet,
// other values are defined as constants.
// If PopStatus == PopStatusOK, then the Attendees will be the common attendees between
// the two nodes.
type CheckConfigReply struct {
	PopStatus int
	PopHash   []byte
	Attendees []abstract.Point
}

// MergeConfig asks if party is ready to merge
type MergeConfig struct {
	// FinalStatement of current party
	Final *FinalStatement
	// Hash of PopDesc party to merge with
	ID []byte
}

type MergeConfigReply struct {
	// status of merging process
	PopStatus int
	// hash of party was asking to merge
	PopHash []byte
	// FinalStatement of party was asked to merge
	Final *FinalStatement
}

// PinRequest will print a random pin on stdout if the pin is empty. If
// the pin is given and is equal to the random pin chosen before, the
// public-key is stored as a reference to the allowed client.
type PinRequest struct {
	Pin    string
	Public abstract.Point
}

// StoreConfig presents a config to store
type StoreConfig struct {
	Desc      *PopDesc
	Signature crypto.SchnorrSig
}

// StoreConfigReply gives back the hash.
// TODO: StoreConfigReply will give in a later version a handler that can be used to
// identify that config.
type StoreConfigReply struct {
	ID []byte
}

// FinalizeRequest asks to finalize on the given descid-popconfig.
// TODO: support more than one popconfig
type FinalizeRequest struct {
	DescID    []byte
	Attendees []abstract.Point
	Signature crypto.SchnorrSig
}

func (fr *FinalizeRequest) Hash() ([]byte, error) {
	h := network.Suite.Hash()
	_, err := h.Write(fr.DescID)
	if err != nil {
		return nil, err
	}
	for _, a := range fr.Attendees {
		b, err := a.MarshalBinary()
		if err != nil {
			return nil, err
		}
		_, err = h.Write(b)
		if err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// FinalizeResponse returns the FinalStatement if all conodes already received
// a PopDesc and signed off. The FinalStatement holds the updated PopDesc, the
// pruned attendees-public-key-list and the collective signature.
type FinalizeResponse struct {
	Final *FinalStatement
}

// FetchRequest asks to get FinalStatement
type FetchRequest struct {
	ID []byte
}

// MergeRequest asks to start merging process for given Party
type MergeRequest struct {
	ID        []byte
	Signature crypto.SchnorrSig
}
