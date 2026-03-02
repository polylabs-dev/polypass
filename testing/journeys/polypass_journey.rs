//! Poly Pass Journey Tests
//!
//! End-to-end journey for Poly Pass: vault creation, credential storage,
//! secure sharing, revocation, breach checking, encryption verification,
//! and blind telemetry — following the eStream Convoy pattern.

use estream_test::{
    Journey, JourneyParty, JourneyStep, StepAction, JourneyMetrics,
    assert_metric_emitted, assert_blinded, assert_povc_witness,
};
use estream_test::convoy::{ConvoyContext, ConvoyResult};
use estream_test::stratum::{StratumVerifier, CsrTier, SeriesMerkleChain};
use estream_test::cortex::{CortexVisibility, RedactPolicy, ObfuscatePolicy};

pub struct PolypassJourney;

impl Journey for PolypassJourney {
    fn name(&self) -> &str {
        "polypass_e2e"
    }

    fn description(&self) -> &str {
        "End-to-end journey for Polypass: vault lifecycle, credential sharing, revocation, breach check, encryption and blind telemetry"
    }

    fn parties(&self) -> Vec<JourneyParty> {
        vec![
            JourneyParty::new("alice")
                .with_spark_context("poly-pass-v1")
                .with_role("vault_owner"),
            JourneyParty::new("bob")
                .with_spark_context("poly-pass-v1")
                .with_role("share_recipient"),
            JourneyParty::new("breach_sentinel")
                .with_spark_context("poly-pass-v1")
                .with_role("breach_monitor"),
        ]
    }

    fn steps(&self) -> Vec<JourneyStep> {
        vec![
            // Step 1: Alice creates an encrypted vault
            JourneyStep::new("alice_creates_vault")
                .party("alice")
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let master_key = ctx.derive_spark_key("poly-pass-v1", "vault_master");

                    let vault = ctx.polypass().create_vault(
                        "personal",
                        &master_key,
                    )?;

                    ctx.set("vault_id", &vault.vault_id);
                    ctx.set("vault_epoch", &vault.epoch.to_string());

                    assert!(!vault.vault_id.is_empty());
                    assert!(vault.encrypted);
                    assert_eq!(vault.kdf, "argon2id");

                    assert_metric_emitted!(ctx, "polypass.vault.created", {
                        "encryption" => "aes256gcm",
                        "kdf" => "argon2id",
                    });

                    assert_povc_witness!(ctx, "polypass.vault.create", {
                        witness_type: "vault_genesis",
                        vault_id: &vault.vault_id,
                    });

                    Ok(())
                }))
                .timeout_ms(10_000),

            // Step 2: Alice stores a credential in the vault
            JourneyStep::new("alice_stores_credential")
                .party("alice")
                .depends_on(&["alice_creates_vault"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let vault_id = ctx.get::<String>("vault_id");

                    let credential = ctx.polypass().store_credential(
                        &vault_id,
                        "github.com",
                        "alice@example.com",
                        "s3cur3-p@ssw0rd!",
                        &[("totp_secret", "JBSWY3DPEHPK3PXP")],
                    )?;

                    ctx.set("credential_id", &credential.credential_id);

                    assert!(!credential.credential_id.is_empty());
                    assert!(credential.password_encrypted);
                    assert!(credential.totp_encrypted);

                    assert_metric_emitted!(ctx, "polypass.credential.stored", {
                        "has_totp" => "true",
                        "site_domain" => "github.com",
                    });

                    assert_blinded!(ctx, "polypass.credential.stored", {
                        field: "password",
                        blinding: "absent",
                    });

                    assert_blinded!(ctx, "polypass.credential.stored", {
                        field: "username",
                        blinding: "hmac_sha3",
                    });

                    Ok(())
                }))
                .timeout_ms(8_000),

            // Step 3: Bob receives a shared credential from Alice
            JourneyStep::new("bob_receives_shared_credential")
                .party("bob")
                .depends_on(&["alice_stores_credential"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let credential_id = ctx.get::<String>("credential_id");
                    let alice_id = ctx.party_id("alice");

                    let share = ctx.polypass().accept_share(
                        &alice_id,
                        &credential_id,
                        &["read"],
                        86_400, // 24h expiry
                    )?;

                    assert!(share.access_granted);
                    assert_eq!(share.permissions, vec!["read"]);
                    assert!(share.expiry_secs > 0);

                    let retrieved = ctx.polypass().get_credential(&credential_id)?;
                    assert_eq!(retrieved.site, "github.com");
                    assert!(retrieved.password_decryptable);

                    assert_metric_emitted!(ctx, "polypass.share.accepted", {
                        "permission_level" => "read",
                        "time_limited" => "true",
                    });

                    assert_blinded!(ctx, "polypass.share.accepted", {
                        field: "recipient_id",
                        blinding: "hmac_sha3",
                    });

                    assert_povc_witness!(ctx, "polypass.share", {
                        witness_type: "credential_share",
                        credential_id: &credential_id,
                    });

                    Ok(())
                }))
                .timeout_ms(10_000),

            // Step 4: Alice revokes Bob's access
            JourneyStep::new("alice_revokes_share")
                .party("alice")
                .depends_on(&["bob_receives_shared_credential"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let credential_id = ctx.get::<String>("credential_id");
                    let bob_id = ctx.party_id("bob");

                    let revoke = ctx.polypass().revoke_share(
                        &credential_id,
                        &bob_id,
                    )?;

                    assert!(revoke.revoked);
                    assert!(revoke.re_encrypted);

                    let bob_ctx = ctx.as_party("bob");
                    let access_attempt = bob_ctx.polypass().get_credential(&credential_id);
                    assert!(access_attempt.is_err());

                    assert_metric_emitted!(ctx, "polypass.share.revoked", {
                        "re_encrypted" => "true",
                    });

                    assert_povc_witness!(ctx, "polypass.revoke", {
                        witness_type: "share_revocation",
                        credential_id: &credential_id,
                    });

                    Ok(())
                }))
                .timeout_ms(8_000),

            // Step 5: Breach sentinel runs a credential leak check
            JourneyStep::new("breach_check_runs")
                .party("breach_sentinel")
                .depends_on(&["alice_revokes_share"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let vault_id = ctx.get::<String>("vault_id");

                    let report = ctx.polypass().run_breach_check(
                        &vault_id,
                        "hibp_k_anon", // k-anonymity based, no plaintext leaves device
                    )?;

                    assert!(report.check_complete);
                    assert!(report.k_anonymity_used);
                    assert!(!report.plaintext_leaked);
                    assert_eq!(report.credentials_checked, 1);

                    assert_metric_emitted!(ctx, "polypass.breach.check_complete", {
                        "method" => "hibp_k_anon",
                        "credentials_checked" => "1",
                    });

                    assert_blinded!(ctx, "polypass.breach.check_complete", {
                        field: "vault_id",
                        blinding: "hmac_sha3",
                    });

                    assert_blinded!(ctx, "polypass.breach.check_complete", {
                        field: "password_hash",
                        blinding: "k_anonymity_prefix",
                    });

                    assert_povc_witness!(ctx, "polypass.breach_check", {
                        witness_type: "breach_scan",
                        vault_id: &vault_id,
                    });

                    Ok(())
                }))
                .timeout_ms(15_000),

            // Step 6: Verify vault encryption via Stratum storage
            JourneyStep::new("verify_vault_encryption")
                .party("alice")
                .depends_on(&["breach_check_runs"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let vault_id = ctx.get::<String>("vault_id");

                    let stratum = StratumVerifier::new(ctx);

                    let csr_report = stratum.verify_csr_tiers(&vault_id)?;
                    assert!(csr_report.tier_matches(CsrTier::Hot));
                    assert!(csr_report.encryption_at_rest);
                    assert!(csr_report.key_derivation_valid);

                    let merkle = stratum.verify_series_merkle_chain(&vault_id)?;
                    assert!(merkle.chain_intact);
                    assert!(merkle.root_hash_valid);
                    assert!(merkle.series_count >= 1);

                    let cortex = CortexVisibility::new(ctx);
                    cortex.assert_redacted("polypass.vault", RedactPolicy::ContentFields)?;
                    cortex.assert_obfuscated("polypass.vault", ObfuscatePolicy::PartyIdentifiers)?;

                    assert_metric_emitted!(ctx, "polypass.stratum.verified", {
                        "csr_tier" => "hot",
                        "chain_intact" => "true",
                        "encrypted_at_rest" => "true",
                    });

                    Ok(())
                }))
                .timeout_ms(12_000),

            // Step 7: Verify blind telemetry and namespace isolation
            JourneyStep::new("verify_blind_telemetry")
                .party("alice")
                .depends_on(&["verify_vault_encryption"])
                .action(StepAction::Execute(|ctx: &mut ConvoyContext| {
                    let telemetry = ctx.streamsight().drain_telemetry("poly-pass-v1");

                    for event in &telemetry {
                        assert_blinded!(ctx, &event.event_type, {
                            field: "user_id",
                            blinding: "hmac_sha3",
                        });

                        assert_blinded!(ctx, &event.event_type, {
                            field: "vault_contents",
                            blinding: "absent",
                        });

                        assert_blinded!(ctx, &event.event_type, {
                            field: "credential_plaintext",
                            blinding: "absent",
                        });
                    }

                    let cortex = CortexVisibility::new(ctx);
                    cortex.assert_redacted("polypass", RedactPolicy::ContentFields)?;
                    cortex.assert_obfuscated("polypass", ObfuscatePolicy::PartyIdentifiers)?;

                    assert!(telemetry.len() >= 6, "Expected at least 6 telemetry events");

                    let namespaces: Vec<&str> = telemetry
                        .iter()
                        .map(|e| e.namespace.as_str())
                        .collect();
                    for ns in &namespaces {
                        assert!(
                            ns.starts_with("poly-pass-v1"),
                            "Telemetry must stay within poly-pass-v1 namespace, found: {}",
                            ns,
                        );
                    }

                    Ok(())
                }))
                .timeout_ms(5_000),
        ]
    }

    fn metrics(&self) -> JourneyMetrics {
        JourneyMetrics {
            expected_events: vec![
                "polypass.vault.created",
                "polypass.credential.stored",
                "polypass.share.accepted",
                "polypass.share.revoked",
                "polypass.breach.check_complete",
                "polypass.stratum.verified",
            ],
            max_duration_ms: 75_000,
            required_povc_witnesses: 5,
            lex_namespace: "poly-pass-v1",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use estream_test::convoy::ConvoyRunner;

    #[tokio::test]
    async fn run_polypass_journey() {
        let runner = ConvoyRunner::new()
            .with_streamsight("poly-pass-v1")
            .with_stratum()
            .with_cortex();

        runner.run(PolypassJourney).await.expect("Polypass journey failed");
    }
}
