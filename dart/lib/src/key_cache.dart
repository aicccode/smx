/// The switch for the per-key caches shared by SM2 and SM9.
///
/// The caches hold only public values (public keys, point tables, pairing
/// values of master public keys) and one-way digests of private keys. They do
/// show, through timing and to anyone who can read process memory, which keys
/// were used recently.
library;

import 'dart:io' show Platform;

bool _enabled = _enabledFromEnvironment();
final List<void Function()> _clearers = [];

bool _enabledFromEnvironment() {
  // Any non-empty value other than "0" disables the caches, so a mistyped
  // "true" still fails safe.
  final value = Platform.environment['SMX_DISABLE_KEY_CACHE'] ?? '';
  return value.isEmpty || value == '0';
}

/// Whether the per-key caches are on.
bool get keyCacheEnabled => _enabled;

/// Registers a function that empties one cache.
void registerKeyCache(void Function() clear) => _clearers.add(clear);

/// Forgets everything held in the per-key caches.
void clearKeyCaches() {
  for (final clear in _clearers) {
    clear();
  }
}

/// Turns the per-key caches on or off; turning them off also empties them.
///
/// They start on unless the environment variable SMX_DISABLE_KEY_CACHE is set.
void setKeyCacheEnabled(bool enabled) {
  _enabled = enabled;
  if (!enabled) clearKeyCaches();
}

/// A small map that empties itself when full and obeys the switch above.
final class KeyCache<K, V> {
  KeyCache(this.capacity) {
    registerKeyCache(_map.clear);
  }

  final int capacity;
  final Map<K, V> _map = {};

  /// Returns the cached value or computes it (and caches it when enabled).
  V lookup(K key, V Function() compute) {
    if (!_enabled) return compute();
    final cached = _map[key];
    if (cached != null) return cached;
    final value = compute();
    if (!_enabled) return value;
    if (_map.length >= capacity) _map.clear();
    _map[key] = value;
    return value;
  }
}
