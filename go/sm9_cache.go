package smx

import (
	"strings"
	"sync"
)

// Master public keys are long-lived and public, and using one costs a pairing that
// depends only on the key (and, for G2 keys, a subgroup check). A small cache keeps the
// parsed key with that pairing value. It holds public data only: user private keys and
// all other secrets are never cached.

const sm9CacheMax = 64

// sm9SignMaster is a parsed signing master public key with g = e(P1, Ppub-s).
type sm9SignMaster struct {
	ppub sm9G2Aff
	g    sm9Fp12
}

// sm9EncMaster is a parsed encryption master public key with g = e(Ppub-e, P2).
type sm9EncMaster struct {
	ppub sm9G1Aff
	g    sm9Fp12
}

var sm9Cache struct {
	sync.Mutex
	sign map[string]*sm9SignMaster
	enc  map[string]*sm9EncMaster
}

// sm9CacheGet returns the cached value for key, or builds it with parse outside the
// lock and stores it, emptying the map first when it is full.
func sm9CacheGet[V any](m *map[string]*V, key string, parse func(string) (*V, bool)) (*V, bool) {
	sm9Cache.Lock()
	v, ok := (*m)[key]
	sm9Cache.Unlock()
	if ok {
		return v, true
	}
	v, ok = parse(key)
	if !ok {
		return nil, false
	}
	sm9Cache.Lock()
	if *m == nil || len(*m) >= sm9CacheMax {
		*m = make(map[string]*V)
	}
	(*m)[strings.Clone(key)] = v
	sm9Cache.Unlock()
	return v, true
}

// sm9SignMasterFor parses a signing master public key (G2, hex), using the cache.
func sm9SignMasterFor(s string) (*sm9SignMaster, bool) {
	return sm9CacheGet(&sm9Cache.sign, s, func(s string) (*sm9SignMaster, bool) {
		p, ok := sm9ParseG2(s)
		if !ok {
			return nil, false
		}
		return &sm9SignMaster{ppub: p, g: sm9Pair(&sm9P1, &p)}, true
	})
}

// sm9EncMasterFor parses an encryption master public key (G1, hex), using the cache.
func sm9EncMasterFor(s string) (*sm9EncMaster, bool) {
	return sm9CacheGet(&sm9Cache.enc, s, func(s string) (*sm9EncMaster, bool) {
		p, ok := sm9ParseG1(s, false)
		if !ok {
			return nil, false
		}
		return &sm9EncMaster{ppub: p, g: sm9Pair(&p, &sm9P2)}, true
	})
}
