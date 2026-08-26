import XCTest
@testable import OlloCrypto

final class SessionVaultTests: XCTestCase {
    private let wrap = Data(repeating: 5, count: 32)

    func testSealsTokensAndWipesOnRefreshReject() throws {
        let store = IdentityStore()
        let proto = ProtocolStore(store: store, wrapKey: wrap)
        try proto.sessionVault.save(SessionSecrets(userId: "u1", deviceId: "d1", access: "access-secret", refresh: "refresh-secret"))
        XCTAssertEqual(try proto.sessionVault.load()?.refresh, "refresh-secret")
        XCTAssertEqual(EnvelopePlanner.onRefreshRejected(), .wipe)
        proto.wipe()
        XCTAssertNil(try SessionVault(store: store, wrapKey: wrap).load())
        XCTAssertTrue(store.isEmpty)
    }

    func testRosterHashChangesWhenACloneDeviceAppears() {
        let ik = Data(repeating: 1, count: 32)
        let one = DeviceRoster.hash([DeviceRoster.Device(deviceId: "d1", identityX25519: ik)])
        let two = DeviceRoster.hash([
            DeviceRoster.Device(deviceId: "d2", identityX25519: ik),
            DeviceRoster.Device(deviceId: "d1", identityX25519: ik),
        ])
        XCTAssertNotEqual(one, two)
        XCTAssertEqual(DeviceRoster.note(previous: one, next: two), .changed)
        XCTAssertEqual(DeviceRoster.note(previous: two, next: two), .unchanged)
    }

    func testReplenishOnlyWhenDepthIsLow() {
        XCTAssertNil(EnvelopePlanner.planPrekeyReplenish(remaining: 20, nextId: 11))
        let plan = EnvelopePlanner.planPrekeyReplenish(remaining: 19, nextId: 11)
        XCTAssertEqual(plan?.count, 100)
        XCTAssertEqual(plan?.startId, 11)
    }

    func testRefusesAnUnsignedExtraGroupMember() throws {
        let members = [
            Membership.Member(userId: "b", role: "member"),
            Membership.Member(userId: "a", role: "admin"),
        ]
        let h1 = try Membership.hash(groupId: "g1", epoch: 1, members: members)
        let h2 = try Membership.hash(groupId: "g1", epoch: 1, members: members.reversed())
        XCTAssertEqual(h1, h2)
        XCTAssertEqual(Membership.planApply(local: nil, incomingEpoch: 1, incomingHash: h1, signatureValid: false, signerRole: "admin"), .drop)
        let plan = Membership.trustedMembers(signedUserIds: ["a", "b"], serverUserIds: ["a", "b", "eve"])
        XCTAssertEqual(Set(plan.trusted), Set(["a", "b"]))
        XCTAssertEqual(plan.extra, ["eve"])
        XCTAssertEqual(
            Set(Membership.planFanoutRecipients(signedUserIds: ["a", "b"], serverUserIds: ["a", "b", "eve"])),
            Set(["a", "b"])
        )
        XCTAssertEqual(Membership.planFanoutRecipients(signedUserIds: [], serverUserIds: ["a", "eve"]), [])
        let alice = Membership.Member(userId: "a", role: "admin")
        let eve = Membership.Member(userId: "eve", role: "member")
        XCTAssertEqual(
            Membership.planApply(
                local: Membership.Local(epoch: 1, hash: h1),
                incomingEpoch: 2,
                incomingHash: "bb",
                signatureValid: true,
                signerRole: "admin",
                signerUserId: "a",
                localMembers: [alice],
                incomingMembers: [alice, eve]
            ),
            .confirm
        )
        XCTAssertEqual(
            Membership.planApply(
                local: Membership.Local(epoch: 1, hash: h1),
                incomingEpoch: 2,
                incomingHash: "bb",
                signatureValid: true,
                signerRole: "admin",
                signerUserId: "eve",
                localMembers: [alice],
                incomingMembers: [eve, Membership.Member(userId: "a", role: "member")]
            ),
            .drop
        )
        XCTAssertEqual(
            Membership.planApply(
                local: Membership.Local(epoch: 1, hash: h1),
                incomingEpoch: 2,
                incomingHash: "bb",
                signatureValid: true,
                signerRole: "admin",
                signerUserId: "a",
                localMembers: [alice],
                incomingMembers: [alice, eve],
                rejectedHashes: ["bb"]
            ),
            .rejected
        )
        XCTAssertEqual(Membership.planSignerNotice(localUserId: "a", localDeviceId: "d1", signerUserId: "a", signerDeviceId: "stolen"), "own-other-device")
        XCTAssertEqual(Membership.planRejectedHashes(existing: ["aa"], nextHash: "bb"), ["aa", "bb"])
        XCTAssertEqual(
            Membership.planApply(
                local: nil,
                incomingEpoch: 1,
                incomingHash: h1,
                signatureValid: true,
                signerRole: "admin",
                localDeviceId: "d1",
                signerDeviceId: "stolen"
            ),
            .confirm
        )
        XCTAssertEqual(Membership.planSenderKeyIngest(trustedUserIds: ["a", "b"], pendingUserIds: ["a", "b", "eve"], senderUserId: "eve"), "hold")
        XCTAssertEqual(Membership.planSenderKeyIngest(trustedUserIds: ["a", "b"], pendingUserIds: ["a", "b"], senderUserId: "eve"), "drop")
        let slots = ["g1:alice:phone:1", "g1:alice:laptop:1", "g1:bob:d:1"]
        XCTAssertEqual(Membership.planSenderKeyPrune(slots: slots), [])
        XCTAssertEqual(Membership.planSenderKeyPrune(slots: slots, userId: "alice", deviceId: "phone"), ["g1:alice:phone:1"])
        XCTAssertEqual(Membership.planDroppedDevices(existing: ["a:d1"], userId: "a", deviceId: "stolen"), ["a:d1", "a:stolen"])
        XCTAssertEqual(
            Membership.planSenderKeyIngest(trustedUserIds: ["alice"], pendingUserIds: [], senderUserId: "alice", senderDeviceId: "phone", droppedDevices: ["alice:phone"]),
            "drop"
        )
        XCTAssertEqual(
            Membership.planSenderKeyIngest(trustedUserIds: ["alice"], pendingUserIds: [], senderUserId: "alice", senderDeviceId: "laptop", droppedDevices: ["alice:phone"]),
            "accept"
        )
        XCTAssertEqual(
            Membership.planOwnOtherHoldDevices(
                localUserId: "a",
                localDeviceId: "d1",
                pending: [
                    (signerUserId: "a", signerDeviceId: "stolen"),
                    (signerUserId: "a", signerDeviceId: "d1"),
                    (signerUserId: "b", signerDeviceId: "d9"),
                ]
            ),
            ["a:stolen"]
        )
        XCTAssertEqual(
            Membership.planSenderKeyIngest(trustedUserIds: ["a"], pendingUserIds: [], senderUserId: "a", senderDeviceId: "stolen", holdDevices: ["a:stolen"]),
            "hold"
        )
        XCTAssertEqual(
            Membership.planSenderKeyIngest(trustedUserIds: ["a"], pendingUserIds: [], senderUserId: "a", senderDeviceId: "stolen", droppedDevices: ["a:stolen"], holdDevices: ["a:stolen"]),
            "drop"
        )
        XCTAssertEqual(
            Membership.planSenderKeyEpochRotate(groups: [
                (groupId: "g1", role: "admin", epoch: 2),
                (groupId: "g2", role: "member", epoch: 4),
                (groupId: "", role: "admin", epoch: 1),
                (groupId: "g3", role: "admin", epoch: 0),
            ]).map { $0.groupId },
            ["g1"]
        )
        XCTAssertEqual(
            Membership.planSenderKeyEpochRotate(groups: [
                (groupId: "g1", role: "admin", epoch: 2),
            ]).first?.nextEpoch,
            3
        )
        XCTAssertEqual(
            Membership.planOwnSenderKeyRotate(groups: [
                (groupId: "g1", role: "admin", epoch: 2),
                (groupId: "g2", role: "member", epoch: 4),
                (groupId: "g3", role: "moderator", epoch: 1),
                (groupId: "", role: "member", epoch: 1),
            ]).map { "\($0.groupId):\($0.epoch)" },
            ["g2:4", "g3:1"]
        )
        XCTAssertEqual(Membership.planGroupEpochAccept(envelopeEpoch: 2, localEpoch: 2), "accept")
        XCTAssertEqual(Membership.planGroupEpochAccept(envelopeEpoch: 1, localEpoch: 2), "drop")
        XCTAssertEqual(Membership.planGroupEpochAccept(envelopeEpoch: 2, localEpoch: nil), "accept")
        XCTAssertEqual(
            Membership.planSenderKeyIngest(
                trustedUserIds: ["alice"],
                pendingUserIds: [],
                senderUserId: "alice",
                incomingEpoch: 1,
                localEpoch: 2
            ),
            "drop"
        )
        XCTAssertEqual(
            Membership.planSenderKeyEpochPrune(slots: ["g1:alice:phone:1", "g1:bob:d:2"], groupId: "g1", keepEpoch: 2),
            ["g1:alice:phone:1"]
        )
        XCTAssertEqual(
            Membership.planOwnSenderKeyEpochPrune(keys: ["g1:1", "g1:2", "g10:2"], groupId: "g1", keepEpoch: 2),
            ["g1:1"]
        )
        let share = Membership.planSenderKeyShare(
            liveAddresses: ["alice:phone", "bob:d1", "bob:d2", "alice:stolen"],
            alreadyShared: ["bob:d1", "carol:gone"],
            localAddress: "alice:phone",
            droppedDevices: ["alice:stolen"]
        )
        XCTAssertEqual(share.missing, ["bob:d2"])
        XCTAssertEqual(share.keep, ["bob:d1"])
        XCTAssertEqual(
            Membership.planSenderKeySharedDrop(
                slots: ["g1:2": ["bob:d1", "bob:d2"], "g2:1": ["bob:d2"]],
                address: "bob:d2"
            ),
            ["g1:2": ["bob:d1"], "g2:1": []]
        )
    }

    func testDropsAReplayedEnvelopeAndClearsOnWipe() throws {
        let store = IdentityStore()
        let proto = ProtocolStore(store: store, wrapKey: wrap)
        XCTAssertEqual(try proto.rememberEnvelope("e1"), .accept)
        XCTAssertEqual(try proto.rememberEnvelope("e1"), .drop)
        XCTAssertEqual(try proto.rememberEnvelope("e2"), .accept)
        var ids = ["a", "b"]
        XCTAssertEqual(EnvelopePlanner.rememberEnvelope(&ids, envelopeId: "c", max: 2), .accept)
        XCTAssertEqual(ids, ["b", "c"])
        proto.wipe()
        XCTAssertEqual(try ProtocolStore(store: store, wrapKey: wrap).rememberEnvelope("e1"), .accept)
    }

    func testControllerRotatesTokensAndWipesOnFailedRefresh() throws {
        let store = IdentityStore()
        let proto = ProtocolStore(store: store, wrapKey: wrap, localUserId: "u1", localDeviceId: "d1")
        try proto.sessions.saveSession(
            SessionDirectory.Address(userId: "u2", deviceId: "d9"),
            record: Data([1, 2, 3])
        )
        let ctl = SessionController(proto: proto)
        try ctl.save(SessionSecrets(userId: "u1", deviceId: "d1", access: "access-1", refresh: "refresh-1"))
        XCTAssertEqual(try ctl.restore()?.access, "access-1")
        XCTAssertTrue(try ctl.applyRefresh(access: "access-2", refresh: "refresh-2"))
        XCTAssertEqual(try proto.sessionVault.load()?.refresh, "refresh-2")
        XCTAssertEqual(ctl.onUnauthorized(refreshSucceeded: true), .retry)
        XCTAssertEqual(ctl.access(), "access-2")
        XCTAssertEqual(ctl.onUnauthorized(refreshSucceeded: false), .wipe)
        XCTAssertNil(ctl.access())
        XCTAssertNil(try proto.sessionVault.load())
        XCTAssertNil(try proto.sessions.loadSession(SessionDirectory.Address(userId: "u2", deviceId: "d9")))
        XCTAssertTrue(store.isEmpty)
    }

    func testLaunchFollowsVaultThenWipe() throws {
        let proto = ProtocolStore(store: IdentityStore(), wrapKey: wrap)
        let ctl = SessionController(proto: proto)
        XCTAssertEqual(try ctl.launch(), .needAuth)
        try ctl.save(SessionSecrets(userId: "u1", deviceId: "d1", access: "access-1", refresh: "refresh-1"))
        XCTAssertEqual(try ctl.launch(), .signedIn)
        ctl.wipe()
        XCTAssertEqual(try ctl.launch(), .needAuth)
        XCTAssertNil(try ctl.restore())
    }
}
