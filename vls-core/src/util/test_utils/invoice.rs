// Largely cribbed from rust-lightning/lightning/src/offers/invoice.rs

use crate::invoice::Invoice;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::{schnorr, PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use core::time::Duration;
use lightning::blinded_path::payment::{
    BlindedPaymentPath, Bolt12OfferContext, PaymentConstraints, PaymentContext,
    UnauthenticatedReceiveTlvs,
};
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::functional_test_utils::TEST_FINAL_CLTV;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::offers::invoice_request::InvoiceRequestFields;
use lightning::offers::merkle::TaggedHash;
use lightning::offers::nonce::Nonce;
use lightning::offers::offer::{OfferBuilder, OfferId, Quantity};
use lightning::sign::EntropySource;
use lightning::types::payment::{PaymentHash, PaymentSecret};

struct TestEntropySource {}
impl EntropySource for TestEntropySource {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        let mut rng = OsRng;
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }
}

fn payer_keys() -> Keypair {
    let secp_ctx = Secp256k1::new();
    Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
}

pub fn payer_sign<T: AsRef<TaggedHash>>(message: &T) -> Result<schnorr::Signature, ()> {
    let secp_ctx = Secp256k1::new();
    let keys = payer_keys();
    Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
}

fn recipient_keys() -> Keypair {
    let secp_ctx = Secp256k1::new();
    Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap())
}

pub fn recipient_sign<T: AsRef<TaggedHash>>(message: &T) -> Result<schnorr::Signature, ()> {
    let secp_ctx = Secp256k1::new();
    let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap());
    Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
}

fn recipient_pubkey() -> PublicKey {
    recipient_keys().public_key()
}

fn pubkey(byte: u8) -> PublicKey {
    let secp_ctx = Secp256k1::new();
    PublicKey::from_secret_key(&secp_ctx, &privkey(byte))
}

fn privkey(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn payment_paths() -> Vec<BlindedPaymentPath> {
    let payment_secret = PaymentSecret([33; 32]);
    let offer_id = OfferId([22; 32]);
    let invoice_request = InvoiceRequestFields {
        payer_signing_pubkey: pubkey(33),
        quantity: None,
        payer_note_truncated: None,
        human_readable_name: None,
    };
    let entropy_source = TestEntropySource {};
    let nonce = Nonce::from_entropy_source(&entropy_source);
    let expanded_key = ExpandedKey::new([42; 32]);
    let utlvs = UnauthenticatedReceiveTlvs {
        payment_secret,
        payment_constraints: PaymentConstraints { max_cltv_expiry: 0, htlc_minimum_msat: 0 },
        payment_context: PaymentContext::Bolt12Offer(Bolt12OfferContext {
            offer_id,
            invoice_request,
        }),
    };
    let tlvs = utlvs.authenticate(nonce, &expanded_key);

    let secp_ctx = Secp256k1::new();
    let blinded_path = BlindedPaymentPath::new(
        &[],
        pubkey(46),
        tlvs,
        u64::MAX,
        TEST_FINAL_CLTV as u16,
        &entropy_source,
        &secp_ctx,
    )
    .unwrap();

    vec![blinded_path]
}

pub(crate) struct FixedEntropy;

impl EntropySource for FixedEntropy {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        [42; 32]
    }
}

// Make a BOLT-12 invoice via Offer -> InvoiceRequest -> Invoice
pub fn make_test_bolt12_invoice(description: &str, payment_hash: PaymentHash) -> Invoice {
    let expanded_key = ExpandedKey::new([42; 32]);
    let entropy = FixedEntropy;
    let nonce = Nonce::from_entropy_source(&entropy);
    let secp_ctx = Secp256k1::new();
    let payment_id = PaymentId([1; 32]);

    Invoice::Bolt12(
        OfferBuilder::new(recipient_pubkey())
            .description(description.into())
            .amount_msats(200_000)
            .build()
            .unwrap()
            .request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
            .unwrap()
            .build_and_sign()
            .unwrap()
            .respond_with(payment_paths(), payment_hash)
            .unwrap()
            .build()
            .unwrap()
            .sign(recipient_sign)
            .unwrap(),
    )
}

pub fn make_test_unsigned_bolt12_invoice(
    signing_pubkey: PublicKey,
    payment_hash: PaymentHash,
) -> UnsignedBolt12Invoice {
    make_test_unsigned_bolt12_invoice_with_params(
        signing_pubkey,
        payment_hash,
        Some(200_000),
        None,
        None,
        Quantity::One,
        Duration::from_secs(1_000),
        None,
        None,
    )
}

pub fn make_test_unsigned_bolt12_invoice_with_params(
    signing_pubkey: PublicKey,
    payment_hash: PaymentHash,
    offer_amount_msats: Option<u64>,
    invoice_request_amount_msats: Option<u64>,
    quantity: Option<u64>,
    supported_quantity: Quantity,
    created_at: Duration,
    relative_expiry_secs: Option<u32>,
    chain: Option<Network>,
) -> UnsignedBolt12Invoice {
    let expanded_key = ExpandedKey::new([42; 32]);
    let entropy = FixedEntropy;
    let nonce = Nonce::from_entropy_source(&entropy);
    let secp_ctx = Secp256k1::new();
    let payment_id = PaymentId([1; 32]);

    let mut offer_builder = OfferBuilder::new(signing_pubkey)
        .description("test bolt12 invoice".into())
        .supported_quantity(supported_quantity);
    if let Some(network) = chain {
        offer_builder = offer_builder.chain(network);
    }
    if let Some(amount_msats) = offer_amount_msats {
        offer_builder = offer_builder.amount_msats(amount_msats);
    }
    let offer = offer_builder.build().unwrap();

    let mut invoice_request_builder =
        offer.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id).unwrap();
    if let Some(network) = chain {
        invoice_request_builder = invoice_request_builder.chain(network).unwrap();
    }
    if let Some(amount_msats) = invoice_request_amount_msats {
        invoice_request_builder = invoice_request_builder.amount_msats(amount_msats).unwrap();
    }
    if let Some(quantity) = quantity {
        invoice_request_builder = invoice_request_builder.quantity(quantity).unwrap();
    }
    let invoice_request = invoice_request_builder.build_and_sign().unwrap();

    let mut invoice_builder =
        invoice_request.respond_with_no_std(payment_paths(), payment_hash, created_at).unwrap();
    if let Some(relative_expiry_secs) = relative_expiry_secs {
        invoice_builder = invoice_builder.relative_expiry(relative_expiry_secs);
    }
    invoice_builder.build().unwrap()
}
