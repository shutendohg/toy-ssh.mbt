// ML-KEM-768 (FIPS 203). The deterministic internal functions are exposed
// so the scheme can be tested without randomness, which is also what the
// official ACVP vectors exercise.

///|
test "ML-KEM-768 sizes match FIPS 203 and OpenSSH's constants" {
  inspect(@crypto.MLKEM768_ENCAPS_KEY_LEN, content="1184")
  inspect(@crypto.MLKEM768_DECAPS_KEY_LEN, content="2400")
  inspect(@crypto.MLKEM768_CIPHERTEXT_LEN, content="1088")
  inspect(@crypto.MLKEM768_SHARED_SECRET_LEN, content="32")
}

///|
/// A deterministic 32-byte value, so tests need no randomness.
fn seed32(tag : Byte) -> Bytes {
  Bytes::makei(32, i => (tag.to_int() + i).to_byte())
}

///|
test "key generation produces the expected key sizes" {
  let (ek, dk) = @crypto.mlkem768_keygen(seed32(b'\x01')[:], seed32(b'\x02')[:])
  inspect(ek.length(), content="1184")
  inspect(dk.length(), content="2400")
  // The decapsulation key embeds the encapsulation key and its hash
  // (FIPS 203 Algorithm 16), so a caller never has to carry both.
  assert_eq(dk[1152:2336].to_owned(), ek)
}

///|
test "encapsulation and decapsulation agree on the shared secret" {
  // The property the whole scheme exists for.
  let (ek, dk) = @crypto.mlkem768_keygen(seed32(b'\x10')[:], seed32(b'\x11')[:])
  let (ct, ss) = @crypto.mlkem768_encaps(ek[:], seed32(b'\x20')[:])
  inspect(ct.length(), content="1088")
  inspect(ss.length(), content="32")
  let ss2 = @crypto.mlkem768_decaps(dk[:], ct[:])
  assert_eq(ss, ss2)
}

///|
test "encapsulation is deterministic in its message and varies with it" {
  let (ek, _) = @crypto.mlkem768_keygen(seed32(b'\x30')[:], seed32(b'\x31')[:])
  let (ct_a, ss_a) = @crypto.mlkem768_encaps(ek[:], seed32(b'\x40')[:])
  let (ct_b, ss_b) = @crypto.mlkem768_encaps(ek[:], seed32(b'\x40')[:])
  assert_eq(ct_a, ct_b)
  assert_eq(ss_a, ss_b)
  let (ct_c, ss_c) = @crypto.mlkem768_encaps(ek[:], seed32(b'\x41')[:])
  assert_not_eq(ct_a, ct_c)
  assert_not_eq(ss_a, ss_c)
}

///|
test "a corrupted ciphertext is rejected implicitly, not reported" {
  // FIPS 203 Algorithm 18: decapsulation never fails. A bad ciphertext
  // yields a secret derived from the key's own rejection value, so an
  // attacker learns nothing from the outcome.
  let (ek, dk) = @crypto.mlkem768_keygen(seed32(b'\x50')[:], seed32(b'\x51')[:])
  let (ct, ss) = @crypto.mlkem768_encaps(ek[:], seed32(b'\x60')[:])
  let broken = ct.to_fixedarray()
  broken[0] = broken[0] ^ b'\x01'
  let ss_bad = @crypto.mlkem768_decaps(
    dk[:],
    Bytes::from_iter(broken.iter())[:],
  )
  inspect(ss_bad.length(), content="32")
  assert_not_eq(ss, ss_bad)
  // The rejection secret is deterministic for a given key and ciphertext.
  let ss_bad2 = @crypto.mlkem768_decaps(
    dk[:],
    Bytes::from_iter(broken.iter())[:],
  )
  assert_eq(ss_bad, ss_bad2)
  // And it differs between keys, because it is keyed by z.
  let (_, dk2) = @crypto.mlkem768_keygen(seed32(b'\x52')[:], seed32(b'\x53')[:])
  assert_not_eq(
    ss_bad,
    @crypto.mlkem768_decaps(dk2[:], Bytes::from_iter(broken.iter())[:]),
  )
}

///|
test "different key pairs do not share secrets" {
  let (ek1, dk1) = @crypto.mlkem768_keygen(
    seed32(b'\x70')[:],
    seed32(b'\x71')[:],
  )
  let (_, dk2) = @crypto.mlkem768_keygen(seed32(b'\x72')[:], seed32(b'\x73')[:])
  let (ct, ss) = @crypto.mlkem768_encaps(ek1[:], seed32(b'\x80')[:])
  assert_eq(@crypto.mlkem768_decaps(dk1[:], ct[:]), ss)
  // dk2 cannot open it, and says so only by producing a different secret.
  assert_not_eq(@crypto.mlkem768_decaps(dk2[:], ct[:]), ss)
}

///|
test "ML-KEM-768 key generation matches the official ACVP vector" {
  // NIST ACVP-Server, gen-val/json-files/ML-KEM-keyGen-FIPS203,
  // internalProjection.json, ML-KEM-768 tcId 26. The keys are pinned by
  // their SHA-256 so the fixture stays readable; a round trip alone cannot
  // catch a transposed matrix or a wrong index order, because a symmetric
  // mistake cancels out.
  let d = @hex.decode(
    "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0",
  )
  let z = @hex.decode(
    "1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0",
  )
  let (ek, dk) = @crypto.mlkem768_keygen(d[:], z[:])
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@xcrypto.sha256(ek))[:]),
    content="4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@xcrypto.sha256(dk))[:]),
    content="7aab35839207f72b310abe36e2daa1cc7ff6f7fa8941e439967cd47d9b437079",
  )
}

///|
/// Long ACVP inputs, kept out of the test bodies for readability. Their
/// SHA-256 is asserted where they are used, so a corrupted paste is caught.
const EK_TC26 : String = "9c6839354086919bc7b8a547ff18b523075fd1706856400952489e4cd13ed8b17a817a3076e0947b860ec9558bd9d3c94df5418a7a7301763999c09996715ce32aacfef767a44969925949cc9b8120cb78953bcf6fb8282427cb3f4cbbc50ab23274493a8ba7e5c09088160fda731b55980867912bac53125b27073bb502afac5e74973e0f3601dc50ce08cc7f3fa44ce331a43f9673be745295e693077264a8e238f0a912c0a59c44d561e2a8bd831541fe869b3110b051100db3517f87510ecad8651ce4998bb648002ba41a5351fa2a4ed94a58cb707214a59f8876176cf82fceb99364971c7c0896e8b62c0544463ff101983c2045981ccd9173eb33ba18483ed915bd11ea950db3a8787c105263242e3a64c748b8b1a5947880c5bf3896e08b4b9916a39fd70c2ff8bd041a2b18e251d16a276e38100a613ea96a86cb3652dcc83f2d31cd9f8b79e42541a66752d191436cf5b5d8350ee7835cdb122855392c1da5c33fda12ad1028f2806861a2ab9c63785fd11e220346322c250936ab819254734a8dc9241971ac90cda6696adb90d1e327dc977841aba38324c8fb2092784942003a0808e5546d034592f03bacc19e3138c9070ccea80a933d536c49e4771091af8a70207d474574c64b9f1c8e47224174061117e98c18897a7b1b3c4478c6558c321a89a84b6c508947cb61c89204fbca43bcaa1d688f768b02e50babebf0c5fb8962b2355973c4193fa92e0ce4b9f8473e154828c986bf63e1cd985c6f0462c9b4374594d226c5e99b8a844978db8dd2839e27138aacf75e917635cec4b407a54f184c22f62981b9f4552fb334ff2b7ff68b470fd61b993c32581cc0f39881a5a6a769a60297f4b0579acbf52a8abb143885886245ca2636e20498959e4f2857ab96706e6409c4164ba88c7193e568e4446120215a6d8499c6b4bc559628a9f481c7db51e2e10df1f4339a647b4ccc0405b79f70a90ca9a8ad07789222ba6e66c3aff42b61baa637af15126c88b2e210a7cad9cb08cbb5123a7f9bb4ad63daaea6b43f9aaba561212823cb898a676c967b2d64f4b6333439f8993bd7b19687248926e077a9700431a59157b9668ee022b6d31343f15c08f14488877dfb30a552c06f96a16f354b9a3f19090b32a043b43256ba5b1088b56a4125588c8746d4099ea21c4f33ad8c5c7c32286dee2ca76fc2651d57aee9d847824ac609b5bfd5c87316c2afe0e153d6326af89987ecb70cf0a0a77fa000e0e0acc2685e2317429c3a7513f42873cb98f669703ae9146919226db58d6c2b93b6f50c7cdab677b505945a0f2523886c1b82a6a7cc7eba9251096d88360d7ef6473acbcd359a0d20414b95c209b2413b1483a3a061386377b28e3896bcd8c5e2692681cc803e1694efb6ce353082ffca4079ea9bb7b2025bcb68990466ed2803ab11516d80325dc4cde3da9e020653e084c45f837c88711df3aa6075741c1283121c8b1c691013969a62b2563e556206cf0810848691c7c408d018617a7300ad943e189a9b44512ef13b669831392f1329e2ac7c623aa044223079139b7f1c213e93682ed86165468377d40884310163a5539f27745e667adf506896ba933b002e4d50b2497ecff09d0bbca4f7e6f9db9e10c643d23701bd6385e163cf71c1e919a6e20a"

///|
const DK_TC86 : String = "859384dfc0c207a6466ccbbc507c26dfeca413e06e46e30cf18528577b76c108c31e1b6efa8b41044a4fb2152d3ff391bc6443b57060ae655b0efcbabc889032ecc986d2a144153c8189505c37c6bb1471e5ea8c1521770d732e88a1a3b0624e5a2a42661c1743677591296b81447169635160f80d61f31c420a5d35f5adfea37e4254be39741e197056082c1bd9390a030b2a63fc37dfa561ae091dd9da11649bb7406464838bc23c872423b7515e3444fb862ba7d51becabcf9b458f302905cff983d00578ad89686721432221782ba7a134e052bba7879a36654c081e4c3b615a1c764c128afbd79ef0d816c7e5af135a51448c14cf3c6172e022741b889da485c208899190bb2cb8090bd2b7f8213213e090b27a9c3c56bf87024bd2e3001cea031be20e959bc1a75281b8a3639f487c12f40786e5458b14747d965e0e294947d6a487d44938d50829d0723a910806b9376e76480141960757cf37e2ac03b4a6767a68381a69f6b45c274c62b800403c1c992d0b84d336560d6b4bfed4a38edcca3c61699d31cb6bb88c10909cc6081d1bc9a549f604373576f2b5b14d453eec5c7673b5a39ffa8b6a223972019f0ee7300bc82da77414e4413648b68fc8e7b51dc6cbf083098c1a2f2cc680e52a9e7a8964eacb2df18b8da1d603317298b797bc17524ea03376ba3b410ff1b1b23526d3eb7a8255380793c5d938861e4983d4d23cad3a34bb256434dcc315c40c8d0a9d2132a595b78dfbb655f9f2361a379047706400e5cfa1654ac779841c0767ac8c1dd27254599137d9f3355328cd34e581e1e1bdd64c082eaa29a7f71610b65766882ca804106ce0bc5e20630a44bc5ff87db491c2cf7746b3150ba03abd907096d8004fa20384fb154f553659bbc451c09c0d42a43035994cc24b4f798bc7c961c6c64c92f2c63e87149d89e98221a9337f0a973226557056952bbc05abba46c7ec6ce1b2721a0487687c16cff6b50cd5bd59443ca765353848aa42323ebed3776c014d60d8a6b6d6b31de26f11c15822991249f76c3130735d2c22d5d4b4550a3428004349073e3f296a286c3a0d6572c383b3fd277439c85a03b42b584c97b5779a2d675b6de024949438aa8700aeebc9ffca10c8b327ca6b917b899d3ed817c4543cdf288b489c2ef3aa2f95f310b0688e3e81aa83005571812a5267781ac21c92f7c41f359de74877c19124fa462b3a181bd885a3c3534f16d99afea4bb6a434ce177c99020c880eb368fd211261172f0bb7ae4270fc9aa6dfdb5985a1c069f1815e9277bee24cdb1ecba0cf2c3c48100f540a24e4050f9b376868098805136e673150c957b73ea3e7bbab076b459d2157e9e501734500bd2b574b9c563a7ca8ad83b6cfbec76727b1d3c61c289958fc8805ae6e4455a5257e8903854e35112b7cd46185ea16339dc0838e118971cba5a78025f86749433a38ab79b58e6e6885003470e208735177f82d738c3f7a52d848b742a75d115a528f4915078632fbb639145668b504c30abb96929a75fec5deae90973b2431d685f74c98d36db263bbb6c73d71974993e13b50242167110262a8eb406c987481eaacd44069d53c2b967003dd2dcb979d81a97f62351344bc40a6b203083918c40aa459ea2e20892514749556294534cb3e3b948f1c0f7a941fde49874c609973a4e845b112456974b3aaf9877b3159b7ed0c4c423889c8a8b1c5b33409a8c6b26f573a6668a5fe0c74ad0ca28304d1c7a498a93bc08921d3943042f986438abcc61a358c6482839a524845b04ffca16cb741f7db5b0afd7b9874b6b53d156b3e036b3d41e963b27ac0c87b411436471591001635e6440903a0b38302a92c8777f264de5290dd1e511bc7c0a68e3266882cedd30aca8928596b7affb28b94d8711e31a8c9e5ac2a9567b55630d5ff8627e52386408a1bb3bc2d6b90a7c33c04aaa60e9046e10d89b41fbb8e3e26cbc27c1c062411436cc22d637dd021cb93b6972cb7aee5c98ad64006b0cd070b0ad99d467158c85852b88666ba1de29cfa3047396a5bddc76b1afaba62d622e17f846e17487a167ca9b45070309526ee08791647cee81b7aff21ca97c7d09a7b0a2880db0110461f168a8f5bafa045864373217b05ed1223fd0b00a1d7810e341c15ce69567e8265110918b857f2546beb5761de3849fde971e2cc649c363c0ef296e2dc94b07499869851ba3032248e4a628294d626c6f38c42530a07952d6b44b650112f77c8df5c5939102090c8188db61f3713e93c4a22a61c91fea79ea06bb1344a5ccd63812f540a8907ffcf62fbdd7344a744095bc5df65047dcf8362a38bff92b5b6098893ae96286f4199f857dc5351b962204807b9421602a0f00222a82b6f4785daf303354f9c097cb74a0723cbfda0553c4b0b4454e1ed11c6926396be9ad5cd16011d333a1a880e123934243542776a0848b0ccc442bcb117c24982c42d10510683e7d534ac47c6631acb187039d098b7de551b868a28ffc42112253aef0f86f4c358c778017b30c0c3510254e6abf50664fb54c197bacbb790c32a935783093c88927b65c5c696c695cab4a845b262219c639c4f07dcf663914094b1db58dd04105d7c6bc32b6392d481bf954abacac7570cb30bdf265e955ac1df3a356ab59c89b0cc6db7ecf4185f81ba9af7ba8ca47bf69a278681c1c8216cabb4887a366204118764669209d502be63bc8f21429e7434b381b55c95c53da864e333c13e7818644788a381215a4954cf3a038dae27ca4684b130268436cc22fa100ebd843d6d9a20dd0b8c4bc8d56899fd3e4272ca1301ac9429986977a9a4910a785990629dffc7ef2093aaa646741825e53ac6c43b962b5624a4d31a5e054436a2b7b880460a52062e4c5c9b2e72225dc2355d44dd6b22a18ca6a05094bf8d3b2a0c58c13777bbe448fd0182b876a596e595ad4e79db6f0c1b4e1435507802e2b539edc25820b23e7127655e11b34a5aaff25c11a7b617ed7083650c9030462a79ab77be63780a45f8ca96dcb15358e56aedc31360b2030010282ca67cde5169993fa808ee475bda0af49c216af9506330c9b0384bd2c3c51b814cff09b3c530ca754e67966c22e44f68650b7117f78235d8425929816526b0a46f647a85a7929b49d677a38418368091590fd1276ee9629e63944db4770b7c22e30b2cffba5b6d46a9a1217b7fa44b54b8266f07554b3ea970cc30d1e92c03f41ce2a2093f58a831a4353e02393cb8969a582d55545ec39a61104ba2e5bf082d0d9573988cc26089b222718d29bcfb365365bd9529c55aaba5635850809b305614091247e8bb47315503a07337ed40ca79d3c8b8d240d3af38c8a7a65ed18047b92600ff09eb509820f0e"

///|
const C_TC86 : String = "f8ffae03ca26e156af3aa562e6f84159596d3a985ae42da4e45171ba7c8a1cfee2549efddc414b27ff697920bfc8a006be1651b0ecd18f91c91f1df9e6332178c3ba45407099c0c5c223e9c88d4bed9742d8a3e1251c6af4b03cf79f2671d8746e7c86eb270f0c54b3362f691387539f5e7b16680ab51c1f93d098d40cb8698827ae9eb1a85f52199589d561a0fb1140fad888ab0b03fce03a9d1d1069f0ffe274362f3f1b656e402e3075efc29cfdcd3d3a4163f74ce6b1566cf4626d14544a2a33ddf5860612af5d337c6b55a7eae01422ca01882baa591f9edda6976e2bfdf945277b4c145cdbea5f22b636dd9761f8edc518c33223fd46d771e39756b26dfd35798d3aa071f90d2250220d4869c59b3cad020b1e786eb8c856d2ab33ffa1605fb61cb91c64de695fcc1d61ba06941b5336cb67e648b4197af2b297f4eed2df996e213d63e0bfb54a86c47b286a9d5059580dad4007e4dc6fb944a53717f325d94eb6a514c13efc445f8e4ebffde3d7b00b955aebce826e4e9568c5e4eb69e0f3be52c7b441cb7f09ee441bc01058183accde0a9473881bf09c992a86c6511319ee5af76fa80079de11ea7c8b9d0947c308345a6586a8eda5d00aa7a26346c3e2c90c1709e52ee7ca292e89e1c22b5447449ae508ba0fe2c801e3a0f6d12e22c93bd98d19ce199aa055d209431fddc46beab5db20fad6b53b93e1e723785ebc29d486fb240d6a4813683e2e71ff05b4f53eb57c068c2c35f0b0ddabd8e17b48f8477747d1d97aff5434d1f09ce1dd325dc2bb5f79523dd4185dd38d3629b6e83f76257bbbdcd6963b1edffbdf4456c6a6d2641f035d08a7ee3a7f1c046cd3be550ab93853fc689913e0e136a83ba15f948d8f229cfd6e12d19c2fddc9f17dfde4b28a7eac09043f1d4f37ddd4923151e837d7c9c9fc4dc9de1576686b50f6934474402d53439d45a015ba6558c3032571e1b3263bc7e6cad549d1050fdd49f9b5cb2024cf543b6fb706b636106b54e938f8ea664d9cbd75ff7042ed9d81546bda255d177d7335a7df06b5d0edc98c6678318f7131ed7564d5344df54802241144502eedcb057be3ca1d3ff8c65fa7487521dc9d4db49265dff8158b4ce2a1893399bcb4bbfcd2c3f7d9c2286eedcd76518026d6586f10a79e02477efd8ff93931b01210c6ad0f75d23a62f68044200597dd277cebab9b5c21c74c5cd74b63a8b6d59789f5c50cace6676c93990db2f7b4f39e00f455ac002c12367d7bfd0cb0327ef077c45382f0454255b2e11a942254608bc41b890172be38e3edd20ed028c37006aa6ed5907c78614748e53b7ee3242a7c1000552eddb67a5436fe8808d53699e9bb3c190f5b966a1fdbb1da68e8fc630d841c63f5fbe7161baa0670bf970c3e617aaac12c83ff3c1d19761b7421685f1f6c9c93eb35900e54f10744d90f4d444e06c45e2a9faef1a96f0b752d4df1df86a9503d8d99cdf8a62622184a919e19df8230e7017d5f411a89da304b67e63cc3e3d901f998f563ca9bd4c9be"

///|
test "ML-KEM-768 encapsulation matches the official ACVP vector" {
  // NIST ACVP-Server, ML-KEM-encapDecap-FIPS203, ML-KEM-768 tcId 26.
  // Long inputs are pinned by SHA-256; the ciphertext and shared secret
  // are what interoperability actually depends on.
  let ek = @hex.decode(EK_TC26)
  let m = @hex.decode(
    "4e77596168711e913965d8175ac3bd76aab08b7f9385a02ae883cf6c6e17dd81",
  )
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@xcrypto.sha256(ek))[:]),
    content="14e61ead72434882f25ab99eebf87d5d4a7f2721aaf4cc316b3abcdcbf1acc83",
  )
  let (ct, ss) = @crypto.mlkem768_encaps(ek[:], m[:])
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@xcrypto.sha256(ct))[:]),
    content="6aa5618fa7e32446603b9b828f0367fde929305f422d29fbbd5e36e98c94f07c",
  )
  inspect(
    @hex.encode(ss[:]),
    content="79d74f6c6c2d916bec47bd828fd9b67295a37f54927fab1263c0d122f1c6f1ed",
  )
}

///|
test "ML-KEM-768 decapsulation matches the official ACVP vector" {
  // Same source, tcId 86. This is the direction a client runs, so a wrong
  // answer here is exactly what would break the key exchange.
  let dk = @hex.decode(DK_TC86)
  let c = @hex.decode(C_TC86)
  inspect(
    @hex.encode(@crypto.fixed_to_bytes(@xcrypto.sha256(dk))[:]),
    content="03eb53081c6f20e013ab6195bd2f18a25e02201c2fb5790687aa709bb2a48f35",
  )
  inspect(
    @hex.encode(@crypto.mlkem768_decaps(dk[:], c[:])[:]),
    content="34cfae7f2ca3b0b9c3e06afeed554c053f6e51d875d3bd3ff0eda2086ee79f3a",
  )
}
