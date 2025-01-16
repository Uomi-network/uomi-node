use frame_support::traits::Get;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;

use crate::types::Cid;

pub type IpfsReturn = Result<Vec<u8>, sp_runtime::offchain::http::Error>;

fn call_endpoint(url: &str, body: Vec<u8>) -> IpfsReturn {
    let deadline = sp_io::offchain
        ::timestamp()
        .add(sp_runtime::offchain::Duration::from_millis(10_000));
    let request = sp_runtime::offchain::http::Request
        ::post(url, vec![body])
        .add_header("Content-Type", "application/json");
    let pending = request
        .deadline(deadline)
        .send()
        .map_err(|_| sp_runtime::offchain::http::Error::IoError)?;
    let response = pending
        .try_wait(deadline)
        .map_err(|_| sp_runtime::offchain::http::Error::DeadlineReached)??;
    if response.code != 200 {
        log::error!("Error calling IPFS API: {:?}", response.code);
        if let Ok(body) = sp_std::str::from_utf8(&response.body().collect::<Vec<u8>>()) {
            log::error!("Response body: {}", body);
        }
        return Err(sp_runtime::offchain::http::Error::Unknown);
    }
    Ok(response.body().collect::<Vec<u8>>())
}

pub fn get_file_from_cid<T: crate::Config>(cid: &Cid) -> IpfsReturn {
    let cid_str = get_cid_str(cid)?;

    let url = format!("{}/cat?arg={}", T::IpfsApiUrl::get(), cid_str);

    let body = format!(r#"{{
                    "arg": "{}"
                }}"#, cid_str);

    call_endpoint(&url, body.clone().into_bytes())
}

pub fn offchain_pin_file<T: crate::Config>(cid: &Cid) -> IpfsReturn {
    let cid_str = get_cid_str(cid)?;

    let url = format!("{}/pin/add?arg={}", T::IpfsApiUrl::get(), cid_str);

    let body = format!(r#"{{
                    "arg": "{}"
                }}"#, cid_str);

    let output = call_endpoint(&url, body.clone().into_bytes().clone())?;

    let body_str = sp_std::str
        ::from_utf8(&output)
        .map_err(|_| sp_runtime::offchain::http::Error::Unknown)?;

    if body_str.contains(cid_str) {
        Ok(output)
    } else {
        Err(sp_runtime::offchain::http::Error::Unknown)
    }
}

pub fn offchain_unpin_file<T: crate::Config>(cid: &Cid) -> IpfsReturn {
    let cid_str = get_cid_str(cid)?;

    let url = format!("{}/pin/rm?arg={}", T::IpfsApiUrl::get(), cid_str);

    let body = get_arg_body(cid_str);

    let output = call_endpoint(&url, body.clone().into_bytes().clone())?;
    let body_str = sp_std::str
        ::from_utf8(&output)
        .map_err(|_| sp_runtime::offchain::http::Error::Unknown)?;

    if body_str.contains(cid_str) {
        Ok(output)
    } else {
        Err(sp_runtime::offchain::http::Error::Unknown)
    }
}

pub fn get_arg_body(cid_str: &str) -> String {
    format!(r#"{{
        "arg": "{}"
    }}"#, cid_str)
}

pub fn get_cid_str(cid: &Cid) -> Result<&str, sp_runtime::offchain::http::Error> {
    return sp_std::str::from_utf8(&cid).map_err(|_| sp_runtime::offchain::http::Error::Unknown);
}
