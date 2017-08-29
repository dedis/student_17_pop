package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestService_CreateIdentity2(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	_, el, s := local.MakeHELS(5, identityService)
	service := s.(*Service)

	keypair := config.NewKeyPair(network.Suite)
	il := NewData(50, keypair.Public, "one")
	ci := &CreateIdentity{}
	ci.Data = il
	ci.Roster = el
	hash, err := ci.Hash()
	log.ErrFatal(err)

	ci.Sig, err = crypto.SignSchnorr(network.Suite, keypair.Secret, hash)
	log.ErrFatal(err)
	service.auth.keys = append(service.auth.keys, keypair.Public)
	msg, cerr := service.CreateIdentity(ci)
	log.ErrFatal(cerr)
	air := msg.(*CreateIdentityReply)

	data := air.Data
	id, ok := service.Identities[string(data.Hash)]
	assert.True(t, ok)
	assert.NotNil(t, id)
}
