// Integration test for BLS12-381 min_pk operations.
//
// Because flutter_rust_bridge requires native library initialization,
// these tests run as integration tests (not unit tests).
//
// Run with: flutter test integration_test/bls_test.dart

import 'dart:typed_data';

import 'package:bls_dart/bls_dart.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Convert hex string to Uint8List.
Uint8List hexToBytes(String hex) {
  hex = hex.replaceAll(' ', '');
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return result;
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(() async {
    await RustLib.init();
  });

  group('bls12381MinPkVerify', () {
    testWidgets('returns false for empty inputs', (tester) async {
      final result = bls12381MinPkVerify(sigBytes: [], pkBytes: [], msg: []);
      expect(result, isFalse);
    });

    testWidgets('returns false for wrong-size signature', (tester) async {
      final result = bls12381MinPkVerify(
        sigBytes: List.filled(48, 0), // Should be 96
        pkBytes: List.filled(48, 0),
        msg: [1, 2, 3],
      );
      expect(result, isFalse);
    });

    testWidgets('returns false for wrong-size public key', (tester) async {
      final result = bls12381MinPkVerify(
        sigBytes: List.filled(96, 0),
        pkBytes: List.filled(32, 0), // Should be 48
        msg: [1, 2, 3],
      );
      expect(result, isFalse);
    });
  });

  group('bls12381MinPkAggregate', () {
    testWidgets('returns empty for empty input', (tester) async {
      final result = bls12381MinPkAggregate(sigsBytes: []);
      expect(result, isEmpty);
    });

    testWidgets('returns empty for malformed signatures', (tester) async {
      final result = bls12381MinPkAggregate(
        sigsBytes: [Uint8List.fromList(List.filled(10, 0))],
      );
      expect(result, isEmpty);
    });
  });

  group('bls12381MinPkVerifyAggregate', () {
    testWidgets('returns false for empty public keys', (tester) async {
      final result = bls12381MinPkVerifyAggregate(
        pksBytes: [],
        msg: [1, 2, 3],
        aggSigBytes: List.filled(96, 0),
      );
      expect(result, isFalse);
    });

    testWidgets('returns false for mismatched sizes', (tester) async {
      final result = bls12381MinPkVerifyAggregate(
        pksBytes: [Uint8List.fromList(List.filled(32, 0))],
        msg: [1, 2, 3],
        aggSigBytes: List.filled(96, 0),
      );
      expect(result, isFalse);
    });
  });
}
