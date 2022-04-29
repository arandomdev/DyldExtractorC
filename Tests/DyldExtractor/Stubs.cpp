#include <gtest/gtest.h>

#include <Converter/Stubs.h>

using namespace Converter;

TEST(Stubs, Symbol_isReExport) {
    SymbolicSet::Symbol symtab = {"test", std::nullopt, std::nullopt};
    EXPECT_FALSE(symtab.isReExport())
        << "Symtab symbol should not be ReExport.";

    SymbolicSet::Symbol reExport = {"test", 0x8, 0};
    EXPECT_TRUE(reExport.isReExport()) << "ReExport is not detected correctly.";

    SymbolicSet::Symbol normal = {"test", 0x0, 1};
    EXPECT_FALSE(normal.isReExport()) << "Normal Export detected incorrectly.";
}

TEST(Stubs, Symbol_lessThan) {
    std::vector<SymbolicSet::Symbol> keySet = {
        {"symtab1-1", std::nullopt, std::nullopt},
        {"symtab1-2", std::nullopt, std::nullopt},
        {"symtab1-3", 1, std::nullopt},
        {"symtab1-4", 0, std::nullopt},

        {"symtab2-1", std::nullopt, 1},
        {"symtab2-2", std::nullopt, 0},
        {"symtab2-3", std::nullopt, 0},

        {"ReExport-1", 9, 1},
        {"ReExport-2", 8, 2},
        {"ReExport-3", 8, 1},
        {"ReExport-4", 8, 1},

        {"Normal-1", 1, 2},
        {"Normal-2", 1, 1},
        {"Normal-3", 0, 1},
        {"Normal-4", 0, 1},

        {"Z_ident", 0, 1},
        {"Z_ident", 0, 0}};

    std::set<SymbolicSet::Symbol> symbolSet(keySet.begin(), keySet.end());

    auto keyIt = keySet.begin();
    for (auto test : symbolSet) {
        auto key = *keyIt;
        EXPECT_TRUE(key.name == test.name && key.flags == test.flags &&
                    key.topLevelOrdinal == test.topLevelOrdinal);
        keyIt++;
    }

    // Test Equal
    SymbolicSet::Symbol a = {"symtab1-1", std::nullopt, std::nullopt};
    SymbolicSet::Symbol b = {"symtab1-1", std::nullopt, std::nullopt};
    EXPECT_TRUE(!(a < b) && !(b < a));

    // Test same
    for (auto key : keySet) {
        EXPECT_FALSE(symbolSet.insert(key).second);
    }
}