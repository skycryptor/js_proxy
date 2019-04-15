function test_private_key(){
    var sc = Scalar.generate_random();
    console.log("Type - ",  typeof sc.valueOf());
    var kp = Proxy.generate_key_pair(sc.valueOf()); // generate key pair
    var sk = kp.get_private_key(); // get private key from keypair

    var sk_b = sk.to_bytes(); // serialize private key as bytearray

    var sk_f = Proxy.private_key_from_bytes(sk_b); // get private key from bytearray

    var sk_f_b = sk_f.to_bytes(); // serialize new private key as bytearray
    assert(bytes_equal(sk_b, sk_f_b), "Private Key from-to bytes");
}

function test_public_key_from_key_pair(){
    var kp = Proxy.generate_key_pair(); // generate key pair
    var pk = kp.get_public_key(); // get public key from keypair

    var pk_b = pk.to_bytes(); // serialize public key as bytearray

    var pk_f = Proxy.public_key_from_bytes(pk_b); // get public key from bytearray

    var pk_f_b = pk_f.to_bytes(); // serialize new public key as bytearray
    assert(bytes_equal(pk_b, pk_f_b), "Public Key from-to bytes");
}

function test_public_key_from_private_key(){
    var kp = Proxy.generate_key_pair();

    var sk = kp.get_private_key(); // get private key from keypair
    var pk = kp.get_public_key(); // get public key fro keypair

    var pk_1 = sk.get_public_key(); // get public key from private key (sk * elliptic_curve_generator)

    assert(bytes_equal(pk.to_bytes(), pk_1.to_bytes()), "Public key from key pair and from private key");
}

function test_re_encryption_key(){
    var kp_A = Proxy.generate_key_pair(); // generate key pair for Alice
    var kp_B = Proxy.generate_key_pair(); // generate key pair for Bob

    var sk_A = kp_A.get_private_key(); // get Alice private key from keypair

    var pk_B = kp_B.get_public_key(); // get Bob public key from keypair

    var rk_AB = Proxy.generate_re_encryption_key(sk_A, pk_B); // generate re-encryption key from Alice to Bob
    var rk_AB_b = rk_AB.to_bytes(); // serialize re-encryption key as bytearray
    var rk_AB_f = Proxy.re_encryption_key_from_bytes(rk_AB_b); // get re-encryption key from bytearray
    var rk_AB_f_b = rk_AB_f.to_bytes(); // serialize new re-encryption key as bytearray

    assert(bytes_equal(rk_AB_b, rk_AB_f_b), "ReEncryption Key from-to bytes");
}
