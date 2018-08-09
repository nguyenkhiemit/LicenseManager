//
//  LicenseManager.swift
//  VntripV2
//
//  Created by Nguyen on 8/9/18.
//  Copyright © 2018 VNTrip OTA. All rights reserved.
//

import UIKit
import Security

class LicenseManager: NSObject {

    private let Account = "HNAUUIDStorage/Account"
    static let shared = LicenseManager()
    public var lastErrorStatus:OSStatus = noErr
    public var accessGroup:String = ""

    override init() {
        super.init()
    }

    public func findOrCreateUUID() -> String? {
        self.lastErrorStatus = noErr
        let uuid = self.find()
        if (uuid != nil) {
            return uuid
        }
        return self.create()
    }

    public func removeUUID() -> Bool {
        self.lastErrorStatus = noErr
        let deleteDict = self.queryForRemove() as CFDictionary
        let status = SecItemDelete(deleteDict)
        return self.verifyStatusAndStoreLastError(status: status)
    }

    public func migrateUUID() -> Bool {
        self.lastErrorStatus = noErr
        let uuidString = self.find()
        if uuidString == nil {
            return false
        }
        let result = self.removeUUID()
        if !result {
            return false
        }
        let createDict = self.query(forCreate: uuidString!) as CFDictionary
        let status = SecItemAdd(createDict, nil)
        return self.verifyStatusAndStoreLastError(status: status)
    }

    public func renewUUID() -> String? {
        self.lastErrorStatus = noErr
        let result = self.removeUUID()
        if (result) {
            return self.create()
        }
        return nil
    }

    /// REMOVE
    private func queryForRemove() -> [AnyHashable: Any] {
        return [kSecClass: kSecClassGenericPassword,
                kSecAttrAccount: Account,
                kSecAttrService: Bundle.main.bundleIdentifier!]
    }

    /// FIND
    private func create() -> String? {
        let uuidString = UUID().uuidString
        let createDict = self.query(forCreate: uuidString) as CFDictionary
        let status = SecItemAdd(createDict, nil)
        if (self.verifyStatusAndStoreLastError(status: status)) {
            return uuidString
        }
        return nil
    }

    private func query(forCreate UUIDString: String) -> [CFString: Any] {
        var items = [kSecClass : kSecClassGenericPassword,
                     kSecAttrAccount : Account,
                     kSecAttrAccessible : kSecAttrAccessibleAfterFirstUnlock,
                     kSecValueData : UUIDString.data(using: String.Encoding.utf8)!,
                     kSecAttrDescription : "",
                     kSecAttrService : Bundle.main.bundleIdentifier!,
                     kSecAttrComment : ""] as [CFString : Any]

        if self.accessGroup.count > 0 {
            items[kSecAttrAccessGroup] = accessGroup
        }
        return items
    }

    private func find() -> String? {
        var result:CFTypeRef?
        let queryDic = queryForFind() as CFDictionary
        let status = SecItemCopyMatching(queryDic, &result)
        if (!self.verifyStatusAndStoreLastError(status: status)) {
            return nil
        }
        let data = result as? Data
        return String(data: data!, encoding: .utf8)
    }

    private func queryForFind() -> [AnyHashable: Any] {
        return [kSecClass: kSecClassGenericPassword,
                kSecAttrAccount: Account,
                kSecAttrService: Bundle.main.bundleIdentifier!,
                kSecReturnData: kCFBooleanTrue]
    }

    private func verifyStatusAndStoreLastError(status: OSStatus) -> Bool {
        let isSuccess: Bool = (status == noErr)
        if isSuccess {
            return true
        }
        lastErrorStatus = status
        return false
    }

}
