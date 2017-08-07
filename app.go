package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path"

	"gopkg.in/dedis/cothority.v1/cosi/check"
	_ "gopkg.in/dedis/cothority.v1/cosi/protocol"
	_ "gopkg.in/dedis/cothority.v1/cosi/service"

	"fmt"
	"io/ioutil"

	"net"

	"strings"

	"bytes"

	"github.com/BurntSushi/toml"
	_ "github.com/dedis/cothority/pop/service"
	"github.com/dedis/student_17_pop/service"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/anon"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/urfave/cli.v1"
)

func init() {
	network.RegisterMessage(Config{})
}

// Config represents either a manager or an attendee configuration.
type Config struct {
	// Public key of org. Used for linking
	OrgPublic abstract.Point
	// Address of the linked conode.
	Address network.Address
	// Map of Final statements of the parties.
	// indexed by hash of party desciption
	Parties map[string]*PartyConfig
	// config-file name
	name string
}

type PartyConfig struct {
	// Private key of attendee or organizer, depending on value
	// of Index.
	Private abstract.Scalar
	// Public key of attendee or organizer, depending on value of
	// index.
	Public abstract.Point
	// Index of the attendee in the final statement. If the index
	// is -1, then this pop holds an organizer.
	Index int
	// Final statement of the party.
	Final *service.FinalStatement
}

func main() {
	appCli := cli.NewApp()
	appCli.Name = "Proof-of-personhood party"
	appCli.Usage = "Handles party-creation, finalizing, pop-token creation, and verification"
	appCli.Version = "0.1"
	appCli.Commands = []cli.Command{}
	appCli.Commands = []cli.Command{
		commandOrg,
		commandAttendee,
		{
			Name:      "check",
			Aliases:   []string{"c"},
			Usage:     "Check if the servers in the group definition are up and running",
			ArgsUsage: "group.toml",
			Action: func(c *cli.Context) error {
				return check.Config(c.Args().First(), false)
			},
		},
	}
	appCli.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "debug,d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
		cli.StringFlag{
			Name:  "config,c",
			Value: "~/.config/cothority/pop",
			Usage: "The configuration-directory of pop",
		},
	}
	appCli.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		return nil
	}
	appCli.Run(os.Args)
}

// links this pop to a cothority
func orgLink(c *cli.Context) error {
	log.Info("Org: Link")
	if c.NArg() == 0 {
		log.Fatal("Please give an IP and optionally a pin")
	}
	cfg, client := getConfigClient(c)

	host, port, err := net.SplitHostPort(c.Args().First())
	if err != nil {
		return err
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return err
	}
	addr := network.NewTCPAddress(fmt.Sprintf("%s:%s", addrs[0], port))
	pin := c.Args().Get(1)
	if err := client.PinRequest(addr, pin, cfg.OrgPublic); err != nil {
		if err.ErrorCode() == service.ErrorWrongPIN && pin == "" {
			log.Info("Please read PIN in server-log")
			return nil
		}
		return err
	}
	cfg.Address = addr
	log.Info("Successfully linked with", addr)
	cfg.write()
	return nil
}

// sets up a configuration
func orgConfig(c *cli.Context) error {
	log.Info("Org: Config")
	if c.NArg() < 1 {
		log.Fatal(`Please give pop_desc.toml and (optionaly)
		merge_party.toml`)
	}
	cfg, client := getConfigClient(c)
	if cfg.Address.String() == "" {
		log.Fatal("No address")
		return errors.New("No address found - please link first")
	}
	desc := &service.PopDesc{}
	pdFile := c.Args().First()
	buf, err := ioutil.ReadFile(pdFile)
	log.ErrFatal(err, "While reading", pdFile)
	err = decodePopDesc(string(buf), desc)
	log.ErrFatal(err, "While decoding", pdFile)
	//desc.Roster = readGroup(c.Args().Get(1))
	if c.NArg() == 2 {
		mergeFile := c.Args().Get(1)
		buf, err = ioutil.ReadFile(mergeFile)
		log.ErrFatal(err, "While reading", mergeFile)
		desc.Parties, err = decodeGroups(string(buf))
		log.ErrFatal(err, "While decoding ", mergeFile)

		// Check that current party is included in merge config
		found := false
		for _, party := range desc.Parties {
			if service.Equal(desc.Roster, party.Roster) {
				found = true
				break
			}
		}
		if !found {
			log.Fatal("party is not included in merge config")
		}
	}
	hash := base64.StdEncoding.EncodeToString(desc.Hash())
	log.Infof("Hash of config: %s", hash)
	//log.ErrFatal(check.Servers(group), "Couldn't check servers")
	log.ErrFatal(client.StoreConfig(cfg.Address, desc))
	if val, ok := cfg.Parties[hash]; !ok {
		kp := config.NewKeyPair(network.Suite)
		cfg.Parties[hash] = &PartyConfig{
			Index: -1,
			Final: &service.FinalStatement{
				Desc:      desc,
				Attendees: []abstract.Point{},
				Signature: []byte{},
			},
			Public:  kp.Public,
			Private: kp.Secret,
		}
	} else {
		val.Final.Desc = desc
	}
	cfg.write()
	return nil
}

// adds a public key to the list
func orgPublic(c *cli.Context) error {
	if c.NArg() < 2 {
		log.Fatal("Please give a public key and hash of a party")
	}
	log.Info("Org: Adding public keys", c.Args().First())
	str := c.Args().First()
	if !strings.HasPrefix(str, "[") {
		str = "[" + str + "]"
	}
	// TODO: better cleanup rules
	str = strings.Replace(str, "\"", "", -1)
	str = strings.Replace(str, "[", "", -1)
	str = strings.Replace(str, "]", "", -1)
	str = strings.Replace(str, "\\", "", -1)
	log.Info("Niceified public keys are:\n", str)
	keys := strings.Split(str, ",")
	cfg, _ := getConfigClient(c)
	party, err := cfg.getPartybyHash(c.Args().Get(1))
	log.ErrFatal(err)
	for _, k := range keys {
		pub, err := crypto.String64ToPub(network.Suite, k)
		if err != nil {
			log.Fatal("Couldn't parse public key:", k, err)
		}
		for _, p := range party.Final.Attendees {
			if p.Equal(pub) {
				log.Fatal("This key already exists")
			}
		}
		party.Final.Attendees = append(party.Final.Attendees, pub)
	}
	cfg.write()
	return nil
}

// finalizes the statement
func orgFinal(c *cli.Context) error {
	log.Info("Org: Final")
	if c.NArg() < 1 {
		log.Fatal("Please give hash of pop-party")
	}
	cfg, client := getConfigClient(c)

	if len(cfg.Parties) == 0 {
		log.Fatal("No configs stored - first store at least one")
	}
	if cfg.Address == "" {
		log.Fatal("Not linked")
	}
	party, err := cfg.getPartybyHash(c.Args().First())
	log.ErrFatal(err)
	if len(party.Final.Signature) > 0 {
		finst, err := party.Final.ToToml()
		log.ErrFatal(err)
		log.Info("Final statement already here:\n", "\n"+string(finst))
		return nil
	}
	fs, cerr := client.Finalize(cfg.Address, party.Final.Desc, party.Final.Attendees)
	log.ErrFatal(cerr)
	party.Final = fs
	cfg.write()
	finst, err := fs.ToToml()
	log.ErrFatal(err)
	log.Info("Created final statement:\n", "\n"+string(finst))
	return nil
}

// sends Merge request
func orgMerge(c *cli.Context) error {
	log.Info("Org:Merge")
	if c.NArg() < 1 {
		log.Fatal("Please give party-hash")
	}
	cfg, client := getConfigClient(c)
	if cfg.Address == "" {
		log.Fatal("Not linked")
	}
	party, err := cfg.getPartybyHash(c.Args().First())
	log.ErrFatal(err)
	if len(party.Final.Signature) <= 0 || party.Final.Verify() != nil {
		log.Info("The local config is not finished yet")
		log.Info("Fetching final statement")
		fs, err := client.FetchFinal(cfg.Address, party.Final.Desc.Hash())
		log.ErrFatal(err)
		if len(fs.Signature) <= 0 || fs.Verify() != nil {
			log.Fatal("Fetched final statement is invalid")
		}
		party.Final = fs
	}

	if len(party.Final.Desc.Parties) <= 0 {
		log.Fatal("there is no parties to merge")
	}
	fs, err := client.Merge(cfg.Address, party.Final.Desc)
	if err != nil {
		return err
	}
	party.Final = fs
	cfg.write()
	finst, err := fs.ToToml()
	log.ErrFatal(err)
	log.Info("Created merged final statement:\n", "\n"+string(finst))
	return nil
}

// creates a new private/public pair
func attCreate(c *cli.Context) error {
	priv := network.Suite.NewKey(random.Stream)
	pub := network.Suite.Point().Mul(nil, priv)
	privStr, err := crypto.ScalarToString64(nil, priv)
	if err != nil {
		return err
	}
	pubStr, err := crypto.PubToString64(nil, pub)
	if err != nil {
		return err
	}
	log.Infof("Private: %s\nPublic: %s", privStr, pubStr)
	return nil
}

// joins a poparty
func attJoin(c *cli.Context) error {
	log.Info("att: join")
	if c.NArg() < 2 {
		log.Fatal("Please give private key and party-hash.")
	}
	privStr := c.Args().First()
	privBuf, err := base64.StdEncoding.DecodeString(privStr)
	log.ErrFatal(err)
	priv := network.Suite.Scalar()
	log.ErrFatal(priv.UnmarshalBinary(privBuf))
	cfg, client := getConfigClient(c)
	party, err := cfg.getPartybyHash(c.Args().Get(1))
	log.ErrFatal(err)
	if len(party.Final.Signature) <= 0 || party.Final.Verify() != nil {
		log.Info("The local config is not finished yet")
		log.Info("Fetching final statement")
		// Need to get the updated version of party config
		// Cause attendee doesn't know,
		// whether it has finished successfully or not
		fs, err := client.FetchFinal(cfg.Address, party.Final.Desc.Hash())
		log.ErrFatal(err)
		if len(fs.Signature) <= 0 || fs.Verify() != nil {
			log.Fatal("Fetched final statement is invalid")
		}
		party.Final = fs
	}
	party.Private = priv
	party.Public = network.Suite.Point().Mul(nil, priv)
	index := -1
	for i, p := range party.Final.Attendees {
		if p.Equal(party.Public) {
			log.Info("Found public key at index", i)
			index = i
		}
	}
	if index == -1 {
		log.Fatal("Didn't find our public key in the final statement!")
	}
	party.Index = index
	cfg.write()
	return nil
}

// signs a message + context
func attSign(c *cli.Context) error {
	log.Info("att: sign")
	cfg, _ := getConfigClient(c)
	if c.NArg() < 3 {
		log.Fatal("Please give msg, context and party hash")
	}
	party, err := cfg.getPartybyHash(c.Args().Get(2))
	log.ErrFatal(err)

	if party.Index == -1 || party.Private == nil || party.Public == nil ||
		!network.Suite.Point().Mul(nil, party.Private).Equal(party.Public) {
		log.Fatal("No public key stored. Please join a party")
	}

	if len(party.Final.Signature) < 0 || party.Final.Verify() != nil {
		log.Fatal("Party is not finilized or signature is not valid")
	}

	msg := []byte(c.Args().First())
	ctx := []byte(c.Args().Get(1))
	Set := anon.Set(party.Final.Attendees)
	sigtag := anon.Sign(network.Suite, random.Stream, msg,
		Set, ctx, party.Index, party.Private)
	sig := sigtag[:len(sigtag)-32]
	tag := sigtag[len(sigtag)-32:]
	log.Infof("\nSignature: %s\nTag: %s", base64.StdEncoding.EncodeToString(sig),
		base64.StdEncoding.EncodeToString(tag))
	return nil
}

// verifies a signature and tag
func attVerify(c *cli.Context) error {
	log.Info("att: verify")
	cfg, _ := getConfigClient(c)
	if c.NArg() < 5 {
		log.Fatal("Please give a msg, context, signature, a tag and party hash")
	}
	party, err := cfg.getPartybyHash(c.Args().Get(4))
	log.ErrFatal(err)

	if party.Index == -1 || party.Private == nil || party.Public == nil ||
		!network.Suite.Point().Mul(nil, party.Private).Equal(party.Public) {
		log.Fatal("No public key stored. Please join a party")
	}

	if len(party.Final.Signature) < 0 || party.Final.Verify() != nil {
		log.Fatal("Party is not finilized or signature is not valid")
	}

	msg := []byte(c.Args().First())
	ctx := []byte(c.Args().Get(1))
	sig, err := base64.StdEncoding.DecodeString(c.Args().Get(2))
	log.ErrFatal(err)
	tag, err := base64.StdEncoding.DecodeString(c.Args().Get(3))
	log.ErrFatal(err)
	sigtag := append(sig, tag...)
	ctag, err := anon.Verify(network.Suite, msg,
		anon.Set(party.Final.Attendees), ctx, sigtag)
	log.ErrFatal(err)
	if !bytes.Equal(tag, ctag) {
		log.Fatalf("Tag and calculated tag are not equal:\n%x - %x", tag, ctag)
	}
	log.Info("Successfully verified signature and tag")
	return nil
}

// getConfigClient returns the configuration and a client-structure.
func getConfigClient(c *cli.Context) (*Config, *service.Client) {
	cfg, err := newConfig(path.Join(c.GlobalString("config"), "config.bin"))
	log.ErrFatal(err)
	return cfg, service.NewClient()
}

// newConfig tries to read the config and returns an organizer-
// config if it doesn't find anything.
func newConfig(fileConfig string) (*Config, error) {
	name := app.TildeToHome(fileConfig)
	if _, err := os.Stat(name); err != nil {
		kp := config.NewKeyPair(network.Suite)
		return &Config{
			OrgPublic: kp.Public,
			Parties:   make(map[string]*PartyConfig),
			name:      name,
		}, nil
	}
	buf, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("couldn't read %s: %s - please remove it",
			name, err)
	}
	_, msg, err := network.Unmarshal(buf)
	if err != nil {
		return nil, fmt.Errorf("error while reading file %s: %s",
			name, err)
	}
	cfg, ok := msg.(*Config)
	if !ok {
		log.Fatal("Wrong data-structure in file", name)
	}
	if cfg.Parties == nil {
		cfg.Parties = make(map[string]*PartyConfig)
	}
	cfg.name = name
	return cfg, nil
}

// write saves the config to the given file.
func (cfg *Config) write() {
	buf, err := network.Marshal(cfg)
	log.ErrFatal(err)
	log.ErrFatal(ioutil.WriteFile(cfg.name, buf, 0660))
}

func (cfg *Config) getPartybyHash(hash string) (*PartyConfig, error) {
	if val, ok := cfg.Parties[hash]; ok {
		return val, nil
	} else {
		return val, onet.NewClientErrorCode(service.ErrorInternal, "No such party")
	}
}

// readGroup fetches group definition file.
func readGroup(name string) *onet.Roster {
	f, err := os.Open(name)
	log.ErrFatal(err, "Couldn't open group definition file")
	roster, err := app.ReadGroupToml(f)
	log.ErrFatal(err, "Error while reading group definition file", err)
	if len(roster.List) == 0 {
		log.ErrFatalf(err, "Empty entity or invalid group defintion in: %s",
			name)
	}
	return roster
}

type PopDescGroupToml struct {
	Name     string
	DateTime string
	Location string
	Servers  []*app.ServerToml `toml:"servers"`
}

func decodePopDesc(buf string, desc *service.PopDesc) error {
	descGroup := &PopDescGroupToml{}
	_, err := toml.Decode(buf, descGroup)
	if err != nil {
		return err
	}
	desc.Name = descGroup.Name
	desc.DateTime = descGroup.DateTime
	desc.Location = descGroup.Location
	entities := make([]*network.ServerIdentity, len(descGroup.Servers))
	for i, s := range descGroup.Servers {
		en, err := toServerIdentity(s, network.Suite)
		if err != nil {
			return err
		}
		entities[i] = en
	}
	desc.Roster = onet.NewRoster(entities)
	return nil
}

type shortDescGroupToml struct {
	Location string
	Servers  []*app.ServerToml `toml:"servers"`
}

// decode config of several groups into array of rosters
func decodeGroups(buf string) ([]*service.ShortDesc, error) {
	decodedGroups := make(map[string][]shortDescGroupToml)
	_, err := toml.Decode(buf, &decodedGroups)
	if err != nil {
		return []*service.ShortDesc{}, err
	}
	groups := decodedGroups["parties"]
	descs := []*service.ShortDesc{}
	for _, descGroup := range groups {
		desc := &service.ShortDesc{}
		desc.Location = descGroup.Location
		entities := make([]*network.ServerIdentity, len(descGroup.Servers))
		for j, s := range descGroup.Servers {
			en, err := toServerIdentity(s, network.Suite)
			if err != nil {
				return []*service.ShortDesc{}, err
			}
			entities[j] = en
		}
		desc.Roster = onet.NewRoster(entities)
		descs = append(descs, desc)
	}
	return descs, nil
}

// TODO: Needs to be public in app package!!!
// toServerIdentity converts this ServerToml struct to a ServerIdentity.
func toServerIdentity(s *app.ServerToml, suite abstract.Suite) (*network.ServerIdentity, error) {
	pubR := strings.NewReader(s.Public)
	public, err := crypto.Read64Pub(suite, pubR)
	if err != nil {
		return nil, err
	}
	si := network.NewServerIdentity(public, s.Address)
	si.Description = s.Description
	return si, nil
}
