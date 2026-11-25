package proto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/maxb1906/jalon/internal/model"
)

const (
	sshMsgKexInit      = 20
	sshMsgKexECDHInit  = 30
	sshMsgKexECDHReply = 31
	sshMaxPacket       = 256 * 1024
)

// Algorithmes considérés comme obsolètes.
var sshObsolete = map[string]bool{
	"diffie-hellman-group1-sha1": true, "diffie-hellman-group14-sha1": true,
	"diffie-hellman-group-exchange-sha1": true, "rsa1024-sha1": true,
	"ssh-dss": true, "ssh-rsa": true, "ssh-rsa-cert-v01@openssh.com": true, "ssh-dss-cert-v01@openssh.com": true,
	"3des-cbc": true, "aes128-cbc": true, "aes192-cbc": true, "aes256-cbc": true, "blowfish-cbc": true,
	"cast128-cbc": true, "arcfour": true, "arcfour128": true, "arcfour256": true,
	"rijndael-cbc@lysator.liu.se": true, "none": true,
	"hmac-md5": true, "hmac-md5-96": true, "hmac-sha1": true, "hmac-sha1-96": true,
	"hmac-md5-etm@openssh.com": true, "hmac-md5-96-etm@openssh.com": true,
	"hmac-sha1-etm@openssh.com": true, "hmac-sha1-96-etm@openssh.com": true, "umac-64@openssh.com": true,
	"umac-64-etm@openssh.com": true,
}

// Échanges de clés que Jalon sait mener jusqu'à la réponse du serveur
// (pour lire la clé d'hôte), dans l'ordre de préférence.
var sshOurKex = []string{
	"curve25519-sha256", "curve25519-sha256@libssh.org",
	"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
}

var sshHostKeyPref = []string{
	"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
	"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss",
}

// kexInit est le contenu d'un SSH_MSG_KEXINIT.
type kexInit struct {
	Kex, HostKey, CiphersCS, CiphersSC, MACsCS, MACsSC, CompCS, CompSC, LangCS, LangSC []string
}

func readNameList(b []byte) ([]string, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("liste tronquée")
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, errors.New("liste tronquée")
	}
	s := string(b[4 : 4+n])
	var l []string
	if s != "" {
		l = strings.Split(s, ",")
	}
	return l, b[4+n:], nil
}

// parseKexInit décode la charge utile d'un KEXINIT.
func parseKexInit(p []byte) (*kexInit, error) {
	if len(p) < 17 || p[0] != sshMsgKexInit {
		return nil, errors.New("KEXINIT attendu")
	}
	b := p[17:]
	k := &kexInit{}
	fields := []*[]string{&k.Kex, &k.HostKey, &k.CiphersCS, &k.CiphersSC, &k.MACsCS, &k.MACsSC, &k.CompCS, &k.CompSC, &k.LangCS, &k.LangSC}
	for _, f := range fields {
		var err error
		*f, b, err = readNameList(b)
		if err != nil {
			return nil, err
		}
	}
	return k, nil
}

func nameList(l []string) []byte {
	s := strings.Join(l, ",")
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	return b
}

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func readSSHString(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("chaîne tronquée")
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, errors.New("chaîne tronquée")
	}
	return b[4 : 4+n], b[4+n:], nil
}

// buildKexInit construit notre KEXINIT : nos échanges de clés, et pour le
// reste les listes du serveur (compatibles par construction).
func buildKexInit(server *kexInit) []byte {
	var kex []string
	for _, k := range sshOurKex {
		if slices.Contains(server.Kex, k) {
			kex = append(kex, k)
		}
	}
	var hk []string
	for _, h := range sshHostKeyPref {
		if slices.Contains(server.HostKey, h) {
			hk = append(hk, h)
		}
	}
	for _, h := range server.HostKey {
		if !slices.Contains(hk, h) {
			hk = append(hk, h)
		}
	}
	p := []byte{sshMsgKexInit}
	cookie := make([]byte, 16)
	_, _ = rand.Read(cookie)
	p = append(p, cookie...)
	for _, l := range [][]string{kex, hk, server.CiphersCS, server.CiphersSC, server.MACsCS, server.MACsSC, server.CompCS, server.CompSC, nil, nil} {
		p = append(p, nameList(l)...)
	}
	p = append(p, 0, 0, 0, 0, 0) // first_kex_packet_follows + réservé
	return p
}

// sshPacket encadre une charge utile (avant NEWKEYS : ni chiffrement ni MAC).
func sshPacket(payload []byte) []byte {
	pad := 8 - (5+len(payload))%8
	if pad < 4 {
		pad += 8
	}
	b := make([]byte, 4+1+len(payload)+pad)
	binary.BigEndian.PutUint32(b, uint32(1+len(payload)+pad))
	b[4] = byte(pad)
	copy(b[5:], payload)
	_, _ = rand.Read(b[5+len(payload):])
	return b
}

func (s *session) readSSHPacket() ([]byte, error) {
	s.deadline()
	var hdr [5]byte
	if _, err := io.ReadFull(s.rd, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	pad := int(hdr[4])
	if n < 1 || n > sshMaxPacket || pad >= int(n) {
		return nil, fmt.Errorf("paquet SSH invalide (%d)", n)
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(s.rd, body); err != nil {
		return nil, err
	}
	return body[:len(body)-pad], nil
}

// ssh lit la bannière et le KEXINIT, puis mène l'échange ECDH jusqu'à la
// réponse du serveur pour obtenir l'empreinte de la clé d'hôte. La session
// est fermée avant NEWKEYS : aucune authentification n'est tentée.
func (s *session) ssh() error {
	if err := s.dial(); err != nil {
		return err
	}
	var version string
	for i := 0; i < 20; i++ {
		l, err := s.readLine()
		if err != nil {
			return err
		}
		if strings.HasPrefix(l, "SSH-") {
			version = l
			break
		}
	}
	if version == "" {
		s.r.Set(model.Fail, "ssh.no_banner")
		return nil
	}
	info := &model.SSHInfo{Version: sanitize(version)}
	s.r.SSH = info
	s.r.Banner = info.Version
	if !strings.HasPrefix(version, "SSH-2.0-") && !strings.HasPrefix(version, "SSH-1.99-") {
		info.Obsolete = append(info.Obsolete, "SSH-1")
		s.r.Set(model.Fail, "ssh.v1", info.Version)
		return nil
	}
	if _, err := fmt.Fprintf(s.conn, "SSH-2.0-Jalon_%s\r\n", strings.ReplaceAll(model.Version, " ", "_")); err != nil {
		return err
	}
	var kp []byte
	for i := 0; i < 5; i++ {
		p, err := s.readSSHPacket()
		if err != nil {
			return err
		}
		if len(p) > 0 && p[0] == sshMsgKexInit {
			kp = p
			break
		}
	}
	k, err := parseKexInit(kp)
	if err != nil {
		return err
	}
	info.Kex, info.HostKeyAlgs = k.Kex, k.HostKey
	info.Ciphers = union(k.CiphersCS, k.CiphersSC)
	info.MACs = union(k.MACsCS, k.MACsSC)
	info.Compression = union(k.CompCS, k.CompSC)
	for _, l := range [][]string{info.Kex, info.HostKeyAlgs, info.Ciphers, info.MACs} {
		for _, a := range l {
			if sshObsolete[a] && !slices.Contains(info.Obsolete, a) {
				info.Obsolete = append(info.Obsolete, a)
			}
		}
	}
	// AEAD : la liste MAC est ignorée si seuls des chiffrements AEAD sont
	// utilisés ; on la signale quand même.
	if err := s.sshHostKey(k, info); err != nil {
		s.r.AddNote(model.Info, "ssh.no_fingerprint", shortErr(err))
	}
	if len(info.Obsolete) > 0 {
		s.r.Set(model.Warn, "ssh.obsolete", info.Version, strings.Join(info.Obsolete, ", "))
	} else {
		s.r.Set(model.OK, "ssh.ok", info.Version)
	}
	if info.Fingerprint != "" {
		s.r.AddNote(model.Info, "ssh.fingerprint", info.HostKeyType, info.Fingerprint)
	}
	s.r.AddNote(model.Info, "ssh.algos", strings.Join(info.Kex, ", "), strings.Join(info.HostKeyAlgs, ", "))
	s.r.AddNote(model.Info, "ssh.ciphers", strings.Join(info.Ciphers, ", "), strings.Join(info.MACs, ", "))
	return nil
}

func union(a, b []string) []string {
	out := append([]string{}, a...)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func (s *session) sshHostKey(server *kexInit, info *model.SSHInfo) error {
	ours := buildKexInit(server)
	var kexName string
	for _, k := range sshOurKex {
		if slices.Contains(server.Kex, k) {
			kexName = k
			break
		}
	}
	if kexName == "" {
		return errors.New("aucun échange de clés ECDH commun")
	}
	var curve ecdh.Curve
	switch kexName {
	case "curve25519-sha256", "curve25519-sha256@libssh.org":
		curve = ecdh.X25519()
	case "ecdh-sha2-nistp256":
		curve = ecdh.P256()
	case "ecdh-sha2-nistp384":
		curve = ecdh.P384()
	default:
		curve = ecdh.P521()
	}
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.deadline()
	if _, err := s.conn.Write(sshPacket(ours)); err != nil {
		return err
	}
	init := append([]byte{sshMsgKexECDHInit}, sshString(priv.PublicKey().Bytes())...)
	if _, err := s.conn.Write(sshPacket(init)); err != nil {
		return err
	}
	for i := 0; i < 5; i++ {
		p, err := s.readSSHPacket()
		if err != nil {
			return err
		}
		if len(p) == 0 || p[0] != sshMsgKexECDHReply {
			continue
		}
		blob, _, err := readSSHString(p[1:])
		if err != nil {
			return err
		}
		typ, _, err := readSSHString(blob)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(blob)
		info.HostKeyType = string(typ)
		info.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		return nil
	}
	return errors.New("pas de réponse KEX_ECDH_REPLY")
}
