package service

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"

	"encoding/base64"
	"fmt"
	"time"
)

var serviceID onet.ServiceID

func init() {
	serviceID = onet.ServiceFactory.ServiceID(Name)
}

func TestMain(m *testing.M) {
	log.MainTest(m, 3)
}

func TestServiceSave(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	servers := local.GenServers(1)
	service := local.GetServices(servers, serviceID)[0].(*Service)
	service.data.Pin = "1234"
	service.save()
	service.data.Pin = ""
	log.ErrFatal(service.tryLoad())
	require.Equal(t, "1234", service.data.Pin)
}
func TestService_PinRequest(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	servers := local.GenServers(1)
	service := local.GetServices(servers, serviceID)[0].(*Service)
	require.Equal(t, "", service.data.Pin)
	pub, _ := network.Suite.Point().Pick(nil, network.Suite.Cipher([]byte("test")))
	_, cerr := service.PinRequest(&PinRequest{"", pub})
	require.NotNil(t, cerr)
	require.NotEqual(t, "", service.data.Pin)
	_, cerr = service.PinRequest(&PinRequest{service.data.Pin, pub})
	log.Error(cerr)
	require.Equal(t, service.data.Public, pub)
}

func TestService_StoreConfig(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	nodes, r, _ := local.GenTree(2, true)
	service := local.GetServices(nodes, serviceID)[0].(*Service)
	desc := &PopDesc{
		Name:     "test",
		DateTime: "tomorrow",
		Roster:   onet.NewRoster(r.List),
	}
	service.data.Public = network.Suite.Point().Null()
	msg, cerr := service.StoreConfig(&StoreConfig{desc})
	log.ErrFatal(cerr)
	_, ok := msg.(*StoreConfigReply)
	require.True(t, ok)
	_, ok = service.data.Finals[string(desc.Hash())]
	require.True(t, ok)
}

func TestService_CheckConfig(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	nodes, r, _ := local.GenTree(2, true)
	descs, atts, srvcs := storeDesc(local.GetServices(nodes, serviceID), r, 2, 2)
	for _, s := range srvcs {
		for _, desc := range descs {
			hash := string(desc.Hash())
			s.data.Finals[hash].Attendees = make([]abstract.Point, len(atts))
			copy(s.data.Finals[hash].Attendees, atts)
		}
	}
	cc := &CheckConfig{[]byte{}, atts}
	srvcs[0].SendRaw(r.List[1], cc)
	require.Nil(t, <-srvcs[0].ccChannel)
	hash := string(descs[0].Hash())
	cc.PopHash = []byte(hash)
	srvcs[0].SendRaw(r.List[1], cc)
	require.NotNil(t, <-srvcs[0].ccChannel)
	require.Equal(t, 2, len(srvcs[0].data.Finals[hash].Attendees))
	require.Equal(t, 2, len(srvcs[1].data.Finals[hash].Attendees))

	cc.Attendees = atts[:1]
	srvcs[0].SendRaw(r.List[1], cc)
	require.NotNil(t, <-srvcs[0].ccChannel)
	require.Equal(t, 1, len(srvcs[0].data.Finals[hash].Attendees))
	require.Equal(t, 1, len(srvcs[1].data.Finals[hash].Attendees))
}

func TestService_CheckConfigReply(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	nodes, r, _ := local.GenTree(2, true)
	descs, atts, srvcs := storeDesc(local.GetServices(nodes, serviceID), r, 2, 2)
	for _, desc := range descs {
		hash := string(desc.Hash())
		s0 := srvcs[0]
		s0.data.Finals[hash].Attendees = make([]abstract.Point, len(atts))
		copy(s0.data.Finals[hash].Attendees, atts)

		ccr := &CheckConfigReply{0, desc.Hash(), atts}
		req := &network.Envelope{
			Msg:            ccr,
			ServerIdentity: nodes[1].ServerIdentity,
		}

		s0.CheckConfigReply(req)
		<-s0.ccChannel
		require.Equal(t, 2, len(s0.data.Finals[hash].Attendees))

		ccr.Attendees = atts[:1]
		req.Msg = ccr
		s0.CheckConfigReply(req)
		<-s0.ccChannel
		require.Equal(t, 2, len(s0.data.Finals[hash].Attendees))

		ccr.PopStatus = PopStatusOK + 1
		req.Msg = ccr
		s0.CheckConfigReply(req)
		<-s0.ccChannel
		require.Equal(t, 1, len(s0.data.Finals[hash].Attendees))
	}
}

func TestService_FinalizeRequest(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	nbrNodes := 3
	nbrAtt := 4
	ndescs := 2
	nodes, r, _ := local.GenTree(nbrNodes, true)

	// Get all service-instances
	descs, atts, services := storeDesc(local.GetServices(nodes, serviceID), r, nbrAtt, ndescs)
	for _, desc := range descs {
		// Clear config of first one
		descHash := desc.Hash()
		delete(services[0].data.Finals, string(descHash))

		// Send a request to all services
		for _, s := range services {
			_, err := s.FinalizeRequest(&FinalizeRequest{descHash, atts})
			require.NotNil(t, err)
		}

		// Create a new config for the first one
		services[0].StoreConfig(&StoreConfig{desc})

		// Send a request to all services but the first one
		for _, s := range services[1:] {
			log.Lvl2("Asking", s, "to finalize")
			_, err := s.FinalizeRequest(&FinalizeRequest{descHash, atts})
			require.NotNil(t, err)
		}

		log.Lvl2("Final finalizing")
		final, err := services[0].FinalizeRequest(&FinalizeRequest{descHash, atts})
		require.Nil(t, err)
		require.NotNil(t, final)
		fin, ok := final.(*FinalizeResponse)
		require.True(t, ok)
		require.Nil(t, fin.Final.Verify())
	}
}

func TestService_FetchFinal(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	nbrNodes := 2
	nbrAtt := 1
	ndescs := 2
	nodes, r, _ := local.GenTree(nbrNodes, true)

	// Get all service-instances
	descs, atts, services := storeDesc(local.GetServices(nodes, serviceID), r, nbrAtt, ndescs)
	for _, desc := range descs {
		descHash := desc.Hash()
		_, err := services[0].FinalizeRequest(&FinalizeRequest{descHash, atts})
		require.NotNil(t, err)
		msg, err := services[1].FinalizeRequest(&FinalizeRequest{descHash, atts})
		require.Nil(t, err)
		require.NotNil(t, msg)
		_, ok := msg.(*FinalizeResponse)
		require.True(t, ok)
	}
	for _, desc := range descs {
		// Fetch final
		descHash := desc.Hash()
		for _, s := range services {
			msg, err := s.FetchFinal(&FetchRequest{descHash})
			require.Nil(t, err)
			require.NotNil(t, msg)
			resp, ok := msg.(*FinalizeResponse)
			require.True(t, ok)
			final := resp.Final
			require.NotNil(t, final)
			require.Equal(t, final.Desc.Hash(), descHash)
			require.Nil(t, final.Verify())
		}
	}
}

func TestService_MergeConfig(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	nbrNodes := 4
	nbrAtt := 4
	nodes, r, _ := local.GenTree(nbrNodes, true)

	descs, atts, srvcs := storeDescMerge(local.GetServices(nodes, serviceID), r, nbrAtt)
	hash := make([]string, nbrNodes/2)
	hash[0] = string(descs[0].Hash())
	hash[1] = string(descs[1].Hash())
	cc := &MergeConfig{srvcs[0].data.Finals[hash[0]], []byte{}}
	srvcs[0].SendRaw(r.List[1], cc)
	require.Nil(t, <-srvcs[0].mcChannel)
	srvcs[0].mcChannel <- nil

	require.Equal(t, nbrAtt, len(atts))

	cc.ID = []byte(hash[1])
	srvcs[0].SendRaw(r.List[2], cc)
	rsp := <-srvcs[0].mcChannel
	require.Nil(t, rsp)
	srvcs[0].mcChannel <- nil
	// finish parties
	for i, desc := range descs {
		descHash := desc.Hash()
		_, err := srvcs[2*i].FinalizeRequest(&FinalizeRequest{descHash,
			atts[2*i : 2*i+2]})
		require.NotNil(t, err)
		msg, err := srvcs[2*i+1].FinalizeRequest(&FinalizeRequest{descHash,
			atts[2*i : 2*i+2]})
		require.Nil(t, err)
		require.NotNil(t, msg)
		_, ok := msg.(*FinalizeResponse)
		require.True(t, ok)
	}

	//log.SetDebugVisible(3)
	log.Info("Group 1, Server:", srvcs[0].ServerIdentity())
	log.Info("Group 1, Server:", srvcs[1].ServerIdentity())
	log.Info("Group 2, Server:", srvcs[2].ServerIdentity())
	log.Info("Group 2, Server:", srvcs[3].ServerIdentity())

	cc.ID = []byte(hash[1])
	srvcs[0].SendRaw(r.List[2], cc)

	for i, s := range srvcs {
		mergeMeta := s.data.MergeMetas[hash[i/2]]
		Eventually(t, func() bool { return len(mergeMeta.servicesSet) == 0 },
			fmt.Sprintf("Server %d servicesSet"))
		Eventually(t, func() bool { return len(descs) == len(mergeMeta.statementsMap) },
			fmt.Sprintf("Server %d statementsMap", i))
	}

	for i, s := range srvcs {
		// first server won't merge because it started process via MergeConfig
		// not MergeRequest
		if i < 1 {
			continue
		}
		Eventually(t,
			func() bool {
				return (nbrAtt == len(s.data.Finals[hash[i/2]].Attendees))
			},
			fmt.Sprintf("Server %d attendees not merged", i))
		Eventually(t,
			func() bool {
				return nbrNodes == len(s.data.Finals[hash[i/2]].Desc.Roster.List)
			},
			fmt.Sprintf("Server %d conodes not merged", i))
	}
	for i, s := range srvcs {
		if i < 1 {
			continue
		}
		Eventually(t,
			func() bool {
				return len(s.data.Finals[hash[i/2]].Signature) > 0 &&
					s.data.Finals[hash[i/2]].Verify() == nil
			},
			fmt.Sprintf("Signature in node %d is created", i))
	}
}

func TestService_MergeRequest(t *testing.T) {
	local := onet.NewTCPTest()
	defer local.CloseAll()
	nbrNodes := 4
	nbrAtt := 4
	nodes, r, _ := local.GenTree(nbrNodes, true)
	descs, atts, srvcs := storeDescMerge(local.GetServices(nodes, serviceID), r, nbrAtt)
	hash := make([]string, nbrNodes/2)
	hash[0] = string(descs[0].Hash())
	hash[1] = string(descs[1].Hash())

	log.SetDebugVisible(2)
	// Wrong party check
	mr := &MergeRequest{[]byte(hash[1])}
	srvcs[0].MergeRequest(mr)
	require.Nil(t, <-srvcs[0].mcChannel)

	require.Equal(t, nbrAtt, len(atts))

	// Not finished
	mr.ID = []byte(hash[0])
	srvcs[0].MergeRequest(mr)
	require.Nil(t, <-srvcs[0].mcChannel)

	// finish parties
	for i, desc := range descs {
		descHash := desc.Hash()
		_, err := srvcs[2*i].FinalizeRequest(&FinalizeRequest{descHash,
			atts[2*i : 2*i+2]})
		require.NotNil(t, err)
		msg, err := srvcs[2*i+1].FinalizeRequest(&FinalizeRequest{descHash,
			atts[2*i : 2*i+2]})
		require.Nil(t, err)
		require.NotNil(t, msg)
		_, ok := msg.(*FinalizeResponse)
		require.True(t, ok)
	}

	log.Lvlf2("Group 1, Server: %s", srvcs[0].ServerIdentity())
	log.Lvlf2("Group 1, Server: %s", srvcs[1].ServerIdentity())
	log.Lvlf2("Group 2, Server: %s", srvcs[2].ServerIdentity())
	log.Lvlf2("Group 2, Server: %s", srvcs[3].ServerIdentity())
	mr.ID = []byte(hash[1])
	srvcs[0].MergeRequest(mr)
	require.NotNil(t, <-srvcs[0].mcChannel)
	for i, s := range srvcs {
		Eventually(t,
			func() bool { return nbrAtt == len(s.data.Finals[hash[i/2]].Attendees) },
			fmt.Sprintf("Server %d not merged", i))
	}

}

func storeDesc(srvcs []onet.Service, el *onet.Roster, nbr int, nprts int) ([]*PopDesc, []abstract.Point, []*Service) {
	descs := make([]*PopDesc, nprts)
	for i := range descs {
		descs[i] = &PopDesc{
			Name:     "test" + string(i),
			DateTime: "2017-07-31 00:00",
			Location: "city" + string(i),
			Roster:   onet.NewRoster(el.List),
		}
	}
	atts := make([]abstract.Point, nbr)
	for i := range atts {
		kp := config.NewKeyPair(network.Suite)
		atts[i] = kp.Public
	}
	sret := []*Service{}
	for _, s := range srvcs {
		sret = append(sret, s.(*Service))
		s.(*Service).data.Public = network.Suite.Point().Null()
		for _, desc := range descs {
			s.(*Service).StoreConfig(&StoreConfig{desc})
		}
	}
	return descs, atts, sret
}

// Number of parties is assumed number of nodes / 2.
// Number of nodes is assumed to be even
func storeDescMerge(srvcs []onet.Service, el *onet.Roster, nbr int) ([]*PopDesc, []abstract.Point, []*Service) {
	rosters := make([]*onet.Roster, len(el.List)/2)
	for i := 0; i < len(el.List); i += 2 {
		rosters[i/2] = onet.NewRoster(el.List[i : i+2])
	}
	descs := make([]*PopDesc, len(rosters))
	copy_descs := make([]*ShortDesc, len(rosters))
	for i := range descs {
		descs[i] = &PopDesc{
			Name:     "name",
			DateTime: "2017-07-31 00:00",
			Location: fmt.Sprintf("city%d", i),
			Roster:   rosters[i],
		}
		copy_descs[i] = &ShortDesc{
			Location: fmt.Sprintf("city%d", i),
			Roster:   rosters[i],
		}
	}

	for _, desc := range descs {
		desc.Parties = copy_descs
	}
	atts := make([]abstract.Point, nbr)
	for i := range atts {
		kp := config.NewKeyPair(network.Suite)
		atts[i] = kp.Public
	}
	sret := []*Service{}
	for i, s := range srvcs {
		sret = append(sret, s.(*Service))
		s.(*Service).data.Public = network.Suite.Point().Null()
		desc := descs[i/2]
		s.(*Service).StoreConfig(&StoreConfig{desc})
	}
	for i, desc := range descs {
		desc.Parties = copy_descs
		log.Infof("Party %d Hash: %s", i, base64.StdEncoding.EncodeToString(desc.Hash()))
		str, _ := desc.toToml()
		log.Info("Desc", str)
	}
	return descs, atts, sret
}

const MAX_WAITING = 1000

func Eventually(t *testing.T, f func() bool, msg string) {
	ticks := 0
	for ; !f() && ticks < MAX_WAITING; ticks++ {
		time.Sleep(time.Millisecond)
	}
	if ticks >= MAX_WAITING {
		require.Fail(t, "Timeout on waiting: "+msg)
	}
	require.True(t, f(), msg)
}
