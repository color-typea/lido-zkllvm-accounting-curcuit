#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include "hash.hpp"

using namespace nil::crypto3;

using hash_type = hashes::sha2<256>;

// using hash_element_value_type = std::remove_extent<hash_type::block_type>::type;
using hash_element_value_type = __uint128_t;
constexpr size_t hash_value_type_size = sizeof(hash_element_value_type);

typename hashes::sha2<256>::block_type bytesToBlockType(const char* bytes) {
    hash_element_value_type high;
    memcpy(&high, bytes, hash_value_type_size);

    hash_element_value_type low;
    memcpy(&low, bytes + hash_value_type_size, hash_value_type_size);

    typename hash_type::block_type result { low, high };
    return result;
}

typename hashes::sha2<256>::block_type lift32BytesIntoBlockType(const std::array<char, 32> &bytes) {
    return bytesToBlockType(bytes.data());
}

// these are precomputed, but essentially ZEROHASHES[0] = 0; ZEROHASHES[i+1] = hash(ZEROHASHES[i], ZEROHASHES[i])
std::array<hash_type::block_type, 40> ZEROHASHES = {
    bytesToBlockType("0000000000000000000000000000000000000000000000000000000000000000"),
    bytesToBlockType("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    bytesToBlockType("db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
    bytesToBlockType("c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
    bytesToBlockType("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
    bytesToBlockType("9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
    bytesToBlockType("d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1"),
    bytesToBlockType("87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
    bytesToBlockType("26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"),
    bytesToBlockType("506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1"),
    bytesToBlockType("ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
    bytesToBlockType("6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220"),
    bytesToBlockType("b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f"),
    bytesToBlockType("df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e"),
    bytesToBlockType("b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784"),
    bytesToBlockType("d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb"),
    bytesToBlockType("8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb"),
    bytesToBlockType("8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab"),
    bytesToBlockType("95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4"),
    bytesToBlockType("f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f"),
    bytesToBlockType("cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa"),
    bytesToBlockType("8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c"),
    bytesToBlockType("feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167"),
    bytesToBlockType("e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7"),
    bytesToBlockType("31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0"),
    bytesToBlockType("21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544"),
    bytesToBlockType("619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765"),
    bytesToBlockType("7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4"),
    bytesToBlockType("848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1"),
    bytesToBlockType("8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636"),
    bytesToBlockType("b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c"),
    bytesToBlockType("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7"),
    bytesToBlockType("c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff"),
    bytesToBlockType("1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5"),
    bytesToBlockType("2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d"),
    bytesToBlockType("328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c"),
    bytesToBlockType("bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327"),
    bytesToBlockType("55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74"),
    bytesToBlockType("f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76"),
    bytesToBlockType("ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f"),
};

bool is_same(
    typename hash_type::block_type block0,
    typename hash_type::block_type block1) {

    return block0[0] == block1[0] && block0[1] == block1[1];
}

typename std::vector<hash_type::block_type> packValuesIntoLeafs(std::vector<uint64_t> values) {
    /// Pack 4 uint64 into one hash_type::block_type
    hash_element_value_type high = 0; // ???
    hash_element_value_type low = 0;
    std::vector<hash_type::block_type> result (1);
    hash_type::block_type block { high, low };
    result.push_back(block);
    return result;
}

typename std::tuple<hash_type::block_type, size_t> merkelize_rec(const std::vector<typename hash_type::block_type> &current_layer, size_t height) {
    if (current_layer.size() == 1) {
        return {current_layer[0], height};
    }

    // technically just ceil, but without floating point operations
    size_t next_layer_size = (current_layer.size() / 2) + (current_layer.size() % 2);
    std::vector<typename hash_type::block_type> next_layer;
    next_layer.reserve(next_layer_size);

    for (auto i = 0; i < current_layer.size(); i += 2) {
        typename hash_type::block_type first = current_layer[i];
        typename hash_type::block_type second = (i+1) < current_layer.size() ? current_layer[i+1] : ZEROHASHES[height];
        next_layer[i/2] = hash_pair<hash_type>(first, second);
    }

    return merkelize_rec(next_layer, height + 1);
}

typename hash_type::block_type merkelize(const std::vector<typename hash_type::block_type> &leafs, size_t tree_height) {
    // Tailcall recursion variant for simplicity - obviously could be "unrolled" into a loop manually if circuits cannot optimize tailcalls
    auto actual_data_hash_and_height = merkelize_rec(leafs, 0);
    hash_type::block_type actual_data_hash = std::get<0>(actual_data_hash_and_height);
    auto actual_data_tree_height = std::get<1>(actual_data_hash_and_height);

    // "fast-forward" to the target tree height
    hash_type::block_type hash = actual_data_hash;
    for (auto height = actual_data_tree_height; height < tree_height; ++height) {
        hash = hash_pair<hash_type>(hash, ZEROHASHES[height]);
    }
    return hash;
}

typename hash_type::block_type mix_in_size(const typename hash_type::block_type root, size_t size) {
    // or high = size? Or something completely different?
    hash_element_value_type low = size;
    hash_element_value_type high = 0;
    hash_type::block_type size_as_block { low, high }; 
    return hash_pair<hash_type>(root, size_as_block);
}

uint64_t sum(std::vector<uint64_t> values) {
    uint64_t result = 0ul;
    for (auto val: values) {
        result += val;
    }
    return result;
}

constexpr size_t BALANCES_TREE_DEPTH = 38;

bool circuitImpl(
    std::vector<uint64_t> values,
    uint64_t expected_sum,
    typename hashes::sha2<256>::block_type expected_hash
) {
    // std::array<unsigned char, 32> hash_as_bytes = {245, 176, 147, 22, 77, 155, 182, 164, 218, 20, 240, 127, 213, 20, 79, 233, 203, 129, 45, 139, 84, 141, 153, 92, 75, 180, 174, 165, 154, 240, 218, 0};
    // hash_type::block_type temp_block = lift32BytesIntoBlockType(hash_as_bytes);
    // return is_same(temp_block, expected_hash)

    auto actual_sum = sum(values);
    if (actual_sum != expected_sum) {
        return false;
    }

    std::vector<typename hash_type::block_type> leafs = packValuesIntoLeafs(values);
    typename hash_type::block_type hash_result = mix_in_size(
        merkelize(leafs, BALANCES_TREE_DEPTH), 
        values.size()
    );

    return is_same(hash_result, expected_hash);
}
