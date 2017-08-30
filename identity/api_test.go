package identity

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/dedis/student_17_pop/pop/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/cothority.v1/cosi/protocol"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func NewTestIdentity(cothority *onet.Roster, majority int, owner string, local *onet.LocalTest, kp *config.KeyPair) *Identity {
	id := NewIdentity(cothority, majority, owner, kp)
	id.Client = local.NewClient(ServiceName)
	return id
}

func TestIdentity_PinRequest(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	servers := local.GenServers(1)
	srvc := local.GetServices(servers, identityService)[0].(*Service)
	require.Equal(t, 0, len(srvc.auth.pins))
	pub, _ := network.Suite.Point().Pick(nil, network.Suite.Cipher([]byte("test")))
	_, cerr := srvc.PinRequest(&PinRequest{"", pub})
	require.NotNil(t, cerr)
	require.NotEqual(t, 0, len(srvc.auth.pins))
	pin := ""
	for t, _ := range srvc.auth.pins {
		pin = t
	}
	_, cerr = srvc.PinRequest(&PinRequest{pin, pub})
	log.Error(cerr)
	require.Equal(t, srvc.auth.keys[0], pub)
}

func TestIdentity_StoreKeys(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	servers := local.GenServers(1)
	el := local.GenRosterFromHost(servers...)
	srvc := local.GetServices(servers, identityService)[0].(*Service)
	keypairAdmin := config.NewKeyPair(network.Suite)
	keypairUser := config.NewKeyPair(network.Suite)

	popDesc := &service.PopDesc{}
	popDesc.Name = "test"
	popDesc.DateTime = "test"
	popDesc.Location = "test"
	popDesc.Roster = el
	popDesc.Parties = make([]*service.ShortDesc, 0)

	final := &service.FinalStatement{}
	final.Desc = popDesc
	final.Attendees = make([]abstract.Point, 1)
	final.Attendees[0] = keypairUser.Public
	hash, err := final.Hash()
	log.ErrFatal(err)

	//Sign Final
	tree := el.GenerateNaryTreeWithRoot(2, srvc.ServerIdentity())
	node, err := srvc.CreateProtocol(cosi.Name, tree)
	log.ErrFatal(err)
	signature := make(chan []byte)
	c := node.(*cosi.CoSi)
	c.RegisterSignatureHook(func(sig []byte) {
		signature <- sig[:64]
	})
	c.Message = hash
	go node.Start()

	final.Signature = <-signature

	srvc.auth.keys = append(srvc.auth.keys, keypairAdmin.Public)

	sig, err := crypto.SignSchnorr(network.Suite, keypairAdmin.Secret, hash)
	log.ErrFatal(err)
	_, cerr := srvc.StoreKeys(&StoreKeys{final, sig})
	require.Nil(t, cerr)
	require.Equal(t, srvc.auth.keys[1], keypairUser.Public)
}

func TestIdentity_DataNewCheck(t *testing.T) {
	l := onet.NewTCPTest()
	hosts, el, _ := l.GenTree(5, true)
	services := l.GetServices(hosts, identityService)
	defer l.CloseAll()

	c1 := createIdentity(l, services, el, "one")

	data2 := c1.Data.Copy()
	kp2 := config.NewKeyPair(network.Suite)
	data2.Device["two"] = &Device{kp2.Public}
	data2.Storage["two"] = "public2"
	log.ErrFatal(c1.ProposeSend(data2))

	log.ErrFatal(c1.ProposeUpdate())
	al := c1.Proposed
	assert.NotNil(t, al)

	o2, ok := al.Device["two"]
	assert.True(t, ok)
	assert.True(t, kp2.Public.Equal(o2.Point))
	pub2, ok := al.Storage["two"]
	assert.True(t, ok)
	assert.Equal(t, "public2", pub2)
}

func TestIdentity_AttachToIdentity(t *testing.T) {
	l := onet.NewTCPTest()
	hosts, el, _ := l.GenTree(5, true)
	services := l.GetServices(hosts, identityService)
	for _, s := range services {
		s.(*Service).clearIdentities()
	}
	defer l.CloseAll()

	c1 := createIdentity(l, services, el, "one")

	c2 := NewTestIdentity(el, 50, "two", l, nil)
	log.ErrFatal(c2.AttachToIdentity(c1.ID))
	for _, s := range services {
		is := s.(*Service)
		is.identitiesMutex.Lock()
		if len(is.Identities) != 1 {
			t.Fatal("The new data hasn't been proposed in all services")
		}
		is.identitiesMutex.Unlock()
	}
}

func TestIdentity_DataUpdate(t *testing.T) {
	l := onet.NewTCPTest()
	hosts, el, _ := l.GenTree(5, true)
	services := l.GetServices(hosts, identityService)
	defer l.CloseAll()

	c1 := createIdentity(l, services, el, "one")

	c2 := NewTestIdentity(el, 50, "two", l, nil)
	c2.ID = c1.ID
	log.ErrFatal(c2.DataUpdate())

	assert.NotNil(t, c2.Data)
	o1 := c2.Data.Device[c1.DeviceName]
	if !o1.Point.Equal(c1.Public) {
		t.Fatal("Owner is not c1")
	}
}

func TestIdentity_CreateIdentity(t *testing.T) {
	l := onet.NewTCPTest()
	hosts, el, _ := l.GenTree(3, true)
	services := l.GetServices(hosts, identityService)
	defer l.CloseAll()
	c := createIdentity(l, services, el, "one")
	// Check we're in the data
	assert.NotNil(t, c.Data)
}

func TestIdentity_DataNewPropose(t *testing.T) {
	l := onet.NewTCPTest()
	hosts, el, _ := l.GenTree(2, true)
	services := l.GetServices(hosts, identityService)
	defer l.CloseAll()

	c1 := createIdentity(l, services, el, "onet")

	data2 := c1.Data.Copy()
	kp2 := config.NewKeyPair(network.Suite)
	data2.Device["two"] = &Device{kp2.Public}
	log.ErrFatal(c1.ProposeSend(data2))

	for _, s := range services {
		is := s.(*Service)
		id1 := is.getIdentityStorage(c1.ID)
		id1.Lock()
		if id1 == nil {
			t.Fatal("Didn't find")
		}
		assert.NotNil(t, id1.Proposed)
		if len(id1.Proposed.Device) != 2 {
			t.Fatal("The proposed data should have 2 entries now")
		}
		id1.Unlock()
	}
}

func TestIdentity_ProposeVote(t *testing.T) {
	l := onet.NewTCPTest()
	hosts, el, _ := l.GenTree(5, true)
	services := l.GetServices(hosts, identityService)
	defer l.CloseAll()
	for _, s := range services {
		log.Lvl3(s.(*Service).Identities)
	}

	c1 := createIdentity(l, services, el, "one1")
	data2 := c1.Data.Copy()
	kp2 := config.NewKeyPair(network.Suite)
	data2.Device["two2"] = &Device{kp2.Public}
	data2.Storage["two2"] = "public2"
	log.ErrFatal(c1.ProposeSend(data2))
	log.ErrFatal(c1.ProposeUpdate())
	log.ErrFatal(c1.ProposeVote(true))

	if len(c1.Data.Device) != 2 {
		t.Fatal("Should have two owners now")
	}
}

func TestIdentity_SaveToStream(t *testing.T) {
	l := onet.NewTCPTest()
	_, el, _ := l.GenTree(5, true)
	defer l.CloseAll()
	id := NewIdentity(el, 50, "one1", nil)
	tmpfile, err := ioutil.TempFile("", "example")
	log.ErrFatal(err)
	defer os.Remove(tmpfile.Name())
	log.ErrFatal(id.SaveToStream(tmpfile))
	tmpfile.Close()
	tmpfile, err = os.Open(tmpfile.Name())
	log.ErrFatal(err)
	id2, err := NewIdentityFromStream(tmpfile)
	assert.NotNil(t, id2)
	log.ErrFatal(err)
	tmpfile.Close()

	if id.Data.Threshold != id2.Data.Threshold {
		t.Fatal("Loaded threshold is not the same")
	}
	p, p2 := id.Data.Device["one1"].Point, id2.Data.Device["one1"].Point
	if !p.Equal(p2) {
		t.Fatal("Public keys are not the same")
	}
	if id.Data.Storage["one1"] != id2.Data.Storage["one1"] {
		t.Fatal("Owners are not the same", id.Data.Storage, id2.Data.Storage)
	}
}

func TestCrashAfterRevocation(t *testing.T) {
	l := onet.NewTCPTest()
	hosts, el, _ := l.GenTree(5, true)
	services := l.GetServices(hosts, identityService)
	defer l.CloseAll()
	keypair := config.NewKeyPair(network.Suite)
	for _, srvc := range services {
		s := srvc.(*Service)
		log.Lvl3(s.Identities)
		s.auth.keys = append(s.auth.keys, keypair.Public)
	}

	c1 := NewIdentity(el, 2, "one", keypair)
	c2 := NewIdentity(el, 2, "two", nil)
	c3 := NewIdentity(el, 2, "three", nil)
	defer c1.Client.Close()
	defer c2.Client.Close()
	defer c3.Client.Close()
	log.ErrFatal(c1.CreateIdentity())
	log.ErrFatal(c2.AttachToIdentity(c1.ID))
	proposeUpVote(c1)
	log.ErrFatal(c3.AttachToIdentity(c1.ID))
	proposeUpVote(c1)
	proposeUpVote(c2)
	log.ErrFatal(c1.DataUpdate())
	log.Lvl2(c1.Data)

	data := c1.GetProposed()
	delete(data.Device, "three")
	log.Lvl2(data)
	log.ErrFatal(c1.ProposeSend(data))
	proposeUpVote(c1)
	proposeUpVote(c2)
	log.ErrFatal(c1.DataUpdate())
	log.Lvl2(c1.Data)

	log.Lvl1("C3 trying to send anyway")
	data = c3.GetProposed()
	c3.ProposeSend(data)
	if c3.ProposeVote(true) == nil {
		t.Fatal("Should not be able to vote")
	}
	log.ErrFatal(c1.ProposeUpdate())
}

func TestVerificationFunction(t *testing.T) {
	l := onet.NewTCPTest()
	hosts, el, _ := l.GenTree(2, true)
	services := l.GetServices(hosts, identityService)
	s0 := services[0].(*Service)
	defer l.CloseAll()
	for _, s := range services {
		log.Lvl3(s.(*Service).Identities)
	}

	c1 := createIdentity(l, services, el, "one1")

	// Hack: create own data-structure with twice our signature
	// and send it directly to the skipblock. Without a proper
	// verification-function, this would pass.
	data2 := c1.Data.Copy()
	kp2 := config.NewKeyPair(network.Suite)
	data2.Device["two2"] = &Device{kp2.Public}
	data2.Storage["two2"] = "public2"
	hash, err := data2.Hash()
	log.ErrFatal(err)
	sig, err := crypto.SignSchnorr(network.Suite, kp2.Secret, hash)
	log.ErrFatal(err)
	data2.Votes["one1"] = &sig
	data2.Votes["two2"] = &sig
	id := s0.getIdentityStorage(c1.ID)
	require.NotNil(t, id, "Didn't find identity")
	_, cerr := s0.skipchain.StoreSkipBlock(id.SCData, nil, data2)
	require.NotNil(t, cerr, "Skipchain accepted our fake block!")

	// Gibberish signature
	sig, err = crypto.SignSchnorr(network.Suite, c1.Private, hash)
	log.ErrFatal(err)
	sig.Response.Add(sig.Response, network.Suite.Scalar().One())
	data2.Votes["one1"] = &sig
	_, cerr = s0.skipchain.StoreSkipBlock(id.SCData, nil, data2)
	require.NotNil(t, cerr, "Skipchain accepted our fake signature!")

	// Unhack: verify that the correct way of doing it works, even if
	// we bypass the identity.
	sig, err = crypto.SignSchnorr(network.Suite, c1.Private, hash)
	log.ErrFatal(err)
	data2.Votes["one1"] = &sig
	_, cerr = s0.skipchain.StoreSkipBlock(id.SCData, nil, data2)
	log.ErrFatal(err)
	log.ErrFatal(c1.DataUpdate())

	if len(c1.Data.Device) != 2 {
		t.Fatal("Should have two owners now")
	}
}

func proposeUpVote(i *Identity) {
	log.ErrFatal(i.ProposeUpdate())
	log.ErrFatal(i.ProposeVote(true))
}

func createIdentity(l *onet.LocalTest, services []onet.Service, el *onet.Roster, name string) *Identity {
	keypair := config.NewKeyPair(network.Suite)
	for _, srvc := range services {
		s := srvc.(*Service)
		s.auth.keys = append(s.auth.keys, keypair.Public)
	}

	c := NewTestIdentity(el, 50, name, l, keypair)
	log.ErrFatal(c.CreateIdentity())
	return c
}
