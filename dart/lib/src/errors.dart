/// The single exception type thrown by this library for invalid input and for
/// failed operations.
///
/// Messages are fixed strings. They never quote keys, plaintexts or other
/// input data.
class SmxException implements Exception {
  /// Creates an exception with a fixed, data-free [message].
  const SmxException(this.message);

  /// What went wrong, without any input data.
  final String message;

  @override
  String toString() => 'SmxException: $message';
}
