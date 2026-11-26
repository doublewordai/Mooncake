// Guards of control_auth: each verdict other than kOk has a case that
// produces it.

#include "control_auth.h"

#include <gtest/gtest.h>

#include "secure/kv_crypto.h"
#include <stdlib.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>

namespace mooncake {
namespace control_auth {
namespace {

const std::string kSecretA(40, 'a');
const std::string kSecretB(40, 'b');
// Keys in the shared key format (secure_env.h): 64 hex digits.
const std::string kKeyHexA(64, 'a');
const std::string kKeyHexB(64, 'b');

std::string WriteTempFile(const std::string &content) {
    char path[] = "/tmp/control_auth_test_keyXXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return "";
    close(fd);
    std::ofstream(path) << content;
    return path;
}

int64_t NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

class ControlAuthTest : public ::testing::Test {
   protected:
    void SetUp() override { ConfigureForTesting(true, kSecretA); }
    void TearDown() override {
        for (const char *v :
             {"MC_SECURE_MODE", "MC_SECURE_KEY", "MC_SECURE_KEY_FILE",
              "MC_SECURE_PREVIOUS_KEY", "MC_SECURE_PREVIOUS_KEY_FILE"})
            unsetenv(v);
        unsetenv("MC_CONTROL_AUTH");
        unsetenv("MC_CONTROL_AUTH_KEY");
        unsetenv("MC_CONTROL_AUTH_KEY_FILE");
        unsetenv("MC_CONTROL_AUTH_MAX_SKEW_MS");
        ResetForTesting();
    }
};

TEST_F(ControlAuthTest, ValidTagVerifiesOnce) {
    auto tag = MakeTag(Domain::kRpcRequest, "bound");
    ASSERT_EQ(tag.size(), kTagSize);
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"), Verdict::kOk);
}

TEST_F(ControlAuthTest, ReplayedTagIsRefused) {
    auto tag = MakeTag(Domain::kRpcRequest, "bound");
    ASSERT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"), Verdict::kOk);
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"),
              Verdict::kReplayed);
}

TEST_F(ControlAuthTest, MissingTagIsRefused) {
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, "", "bound"), Verdict::kMissing);
}

TEST_F(ControlAuthTest, MalformedTagIsRefused) {
    auto tag = MakeTag(Domain::kRpcRequest, "bound");
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag.substr(1), "bound"),
              Verdict::kMalformed);
    tag[0] = 'X';
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"),
              Verdict::kMalformed);
}

TEST_F(ControlAuthTest, WrongKeyIsRefused) {
    auto tag = MakeTag(Domain::kRpcRequest, "bound");
    ConfigureForTesting(true, kSecretB);
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"), Verdict::kBadMac);
}

TEST_F(ControlAuthTest, AlteredDataIsRefused) {
    auto tag = MakeTag(Domain::kRpcRequest, "bound");
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bounD"), Verdict::kBadMac);
}

TEST_F(ControlAuthTest, AlteredTimestampIsRefused) {
    auto tag = MakeTag(Domain::kRpcRequest, "bound");
    tag[kTagMagicSize + 7] ^= 1;  // shift the timestamp by a millisecond
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"), Verdict::kBadMac);
}

TEST_F(ControlAuthTest, TagForAnotherDomainIsRefused) {
    auto tag = MakeTag(Domain::kHandshake, "bound");
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"), Verdict::kBadMac);
}

TEST_F(ControlAuthTest, StaleTimestampIsRefused) {
    ConfigureForTesting(true, kSecretA, /*max_skew_ms=*/5000);
    auto old_tag =
        MakeTagAtForTesting(Domain::kRpcRequest, "bound", NowMs() - 6000);
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, old_tag, "bound"),
              Verdict::kStale);
    auto future_tag =
        MakeTagAtForTesting(Domain::kRpcRequest, "bound", NowMs() + 6000);
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, future_tag, "bound"),
              Verdict::kStale);
    auto fresh_tag =
        MakeTagAtForTesting(Domain::kRpcRequest, "bound", NowMs() - 4000);
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, fresh_tag, "bound"),
              Verdict::kOk);
}


TEST_F(ControlAuthTest, EnabledWithoutKeyFailsClosed) {
    auto tag = MakeTag(Domain::kRpcRequest, "bound");
    ConfigureForTesting(true, "");
    EXPECT_TRUE(Enabled());
    EXPECT_FALSE(Ready());
    EXPECT_TRUE(MakeTag(Domain::kRpcRequest, "bound").empty());
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"),
              Verdict::kNotReady);
}

TEST_F(ControlAuthTest, OffByDefault) {
    ResetForTesting();
    unsetenv("MC_CONTROL_AUTH");
    EXPECT_FALSE(Enabled());
    EXPECT_TRUE(MakeTag(Domain::kRpcRequest, "bound").empty());
}

TEST_F(ControlAuthTest, LoadsKeyFromFileIgnoringTrailingNewline) {
    const std::string path = WriteTempFile(kKeyHexA + "\n");
    ASSERT_FALSE(path.empty());
    setenv("MC_CONTROL_AUTH", "1", 1);
    setenv("MC_CONTROL_AUTH_KEY_FILE", path.c_str(), 1);
    ResetForTesting();
    EXPECT_TRUE(Ready()) << ConfigError();
    auto tag = MakeTag(Domain::kRpcRequest, "bound");
    // The same key given inline derives the same key.
    unsetenv("MC_CONTROL_AUTH_KEY_FILE");
    setenv("MC_CONTROL_AUTH_KEY", kKeyHexA.c_str(), 1);
    ResetForTesting();
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"), Verdict::kOk);
    std::remove(path.c_str());
}

// One switch and one key file configure both halves of secure mode, and the
// old control-plane names are aliases of the shared ones.
TEST_F(ControlAuthTest, OneSwitchAndKeyFileTurnOnBothHalves) {
    const std::string path = WriteTempFile(kKeyHexA + "\n");
    ASSERT_FALSE(path.empty());
    setenv("MC_SECURE_MODE", "1", 1);
    setenv("MC_SECURE_KEY_FILE", path.c_str(), 1);
    ResetForTesting();
    ASSERT_TRUE(Ready()) << ConfigError();
    auto data = secure::SecureContext::CreateForTesting(
        secure::SecureConfig::FromEnv(), nullptr);
    EXPECT_TRUE(data->enabled());
    EXPECT_FALSE(data->failed()) << data->reason();
    auto tag = MakeTag(Domain::kRpcRequest, "bound");

    unsetenv("MC_SECURE_MODE");
    unsetenv("MC_SECURE_KEY_FILE");
    setenv("MC_CONTROL_AUTH", "1", 1);
    setenv("MC_CONTROL_AUTH_KEY", kKeyHexA.c_str(), 1);
    ResetForTesting();
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, tag, "bound"), Verdict::kOk);
    EXPECT_TRUE(secure::SecureConfig::FromEnv().enabled);
    std::remove(path.c_str());
}

// A tag made under the previous key still verifies after a rotation, and
// not once that key is dropped.
TEST_F(ControlAuthTest, PreviousKeyVerifiesDuringRotation) {
    setenv("MC_SECURE_MODE", "1", 1);
    setenv("MC_SECURE_KEY", kKeyHexA.c_str(), 1);
    ResetForTesting();
    auto old_tag = MakeTag(Domain::kRpcRequest, "bound");
    auto old_tag2 = MakeTag(Domain::kRpcRequest, "bound");
    setenv("MC_SECURE_KEY", kKeyHexB.c_str(), 1);
    setenv("MC_SECURE_PREVIOUS_KEY", kKeyHexA.c_str(), 1);
    ResetForTesting();
    ASSERT_TRUE(Ready()) << ConfigError();
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, old_tag, "bound"), Verdict::kOk);
    unsetenv("MC_SECURE_PREVIOUS_KEY");
    ResetForTesting();
    EXPECT_EQ(VerifyTag(Domain::kRpcRequest, old_tag2, "bound"),
              Verdict::kBadMac);
}

TEST_F(ControlAuthTest, DisagreeingSwitchesFailClosed) {
    setenv("MC_SECURE_MODE", "0", 1);
    setenv("MC_CONTROL_AUTH", "1", 1);
    setenv("MC_SECURE_KEY", kKeyHexA.c_str(), 1);
    ResetForTesting();
    EXPECT_TRUE(Enabled());
    EXPECT_FALSE(Ready());
}

TEST_F(ControlAuthTest, ShortSecretFailsClosed) {
    setenv("MC_CONTROL_AUTH", "1", 1);
    setenv("MC_CONTROL_AUTH_KEY", "too-short", 1);
    ResetForTesting();
    EXPECT_TRUE(Enabled());
    EXPECT_FALSE(Ready());
}

TEST_F(ControlAuthTest, MissingSecretFailsClosed) {
    setenv("MC_CONTROL_AUTH", "on", 1);
    ResetForTesting();
    EXPECT_TRUE(Enabled());
    EXPECT_FALSE(Ready());
}

TEST_F(ControlAuthTest, UnrecognisedSwitchValueFailsClosed) {
    setenv("MC_CONTROL_AUTH", "ture", 1);
    setenv("MC_CONTROL_AUTH_KEY", kKeyHexA.c_str(), 1);
    ResetForTesting();
    EXPECT_TRUE(Enabled());
    EXPECT_FALSE(Ready());
}

}  // namespace
}  // namespace control_auth
}  // namespace mooncake
