package ingest

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/ipfs/go-datastore"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
	"golang.org/x/crypto/pbkdf2"
)

const (
	mhToEncPeerIDPrefix     = "/es/mh2ep/"
	encPeerIDToPeerIdPrefix = "/es/ep2p/"
	iterations              = 1000
	keyLen                  = 32
	saltLen                 = 8
	ivLen                   = 12
)

type encMapper struct {
	ds  datastore.Datastore
	cdc codec
}

type encValue struct {
	salt []byte
	iv   []byte
	val  []byte
}

type codec interface {
	marshal(val *encValue) ([]byte, error)
	unmarshal([]byte) (*encValue, error)
}

type binaryCodec struct {
}

func NewEncMapper(ds datastore.Datastore) *encMapper {
	return &encMapper{
		ds:  ds,
		cdc: &binaryCodec{},
	}
}

func (em *encMapper) Put(ctx context.Context, mh, dmh multihash.Multihash, peerID string) error {
	derivedKey, salt, err := em.deriveKey([]byte(mh))
	if err != nil {
		return err
	}

	iv := make([]byte, 12)
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	encPeerID := aesgcm.Seal(nil, iv, []byte(peerID), nil)

	marshalled, err := em.cdc.marshal(&encValue{
		salt: salt,
		iv:   iv,
		val:  encPeerID,
	})
	if err != nil {
		return err
	}

	dsKey := em.newKey(dmh)
	return em.ds.Put(ctx, dsKey, marshalled)
}

func (em *encMapper) newKey(mh multihash.Multihash) datastore.Key {
	return datastore.NewKey(adProcessedPrefix + mh.HexString())
}

func (em *encMapper) deriveKey(passphrase []byte) ([]byte, []byte, error) {
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, err
	}
	return pbkdf2.Key([]byte(passphrase), salt, iterations, keyLen, sha256.New), salt, nil
}

func (cdc *binaryCodec) marshal(val *encValue) ([]byte, error) {
	var buf bytes.Buffer
	sl := len(val.salt)
	usl := uint64(sl)
	il := len(val.iv)
	uil := uint64(il)
	vl := len(val.val)
	uvl := uint64(vl)
	buf.Grow(sl + il + vl + varint.UvarintSize(usl) + varint.UvarintSize(uil) + varint.UvarintSize(uvl))
	buf.Write(varint.ToUvarint(usl))
	buf.Write(val.salt)
	buf.Write(varint.ToUvarint(uil))
	buf.Write(val.iv)
	buf.Write(varint.ToUvarint(uvl))
	buf.Write(val.val)
	return buf.Bytes(), nil
}

func (cdc *binaryCodec) unmarshal(b []byte) (*encValue, error) {
	var v encValue
	buf := bytes.NewBuffer(b)

	salt, err := cdc.readByteArray(buf)
	if err != nil {
		return nil, err
	}
	v.salt = salt

	iv, err := cdc.readByteArray(buf)
	if err != nil {
		return nil, err
	}
	v.iv = iv

	val, err := cdc.readByteArray(buf)
	if err != nil {
		return nil, err
	}
	v.val = val
	return &v, nil
}

func (cdc *binaryCodec) readByteArray(buf *bytes.Buffer) ([]byte, error) {
	usize, err := varint.ReadUvarint(buf)
	if err != nil {
		return nil, err
	}
	size := int(usize)
	if size < 0 || size > buf.Len() {
		return nil, errors.New("invalid length")
	}
	return buf.Next(size), nil
}
