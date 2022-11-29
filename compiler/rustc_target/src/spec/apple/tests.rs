use crate::spec::{
    aarch64_apple_darwin, aarch64_apple_ios_sim, aarch64_apple_watchos_sim, apple_base::Arch, cvs,
    i686_apple_darwin, x86_64_apple_darwin, x86_64_apple_ios, x86_64_apple_tvos,
    x86_64_apple_watchos_sim, Cc, LinkerFlavor, Lld,
};

#[test]
fn simulator_targets_set_abi() {
    let all_sim_targets = [
        x86_64_apple_ios::target(),
        x86_64_apple_tvos::target(),
        x86_64_apple_watchos_sim::target(),
        aarch64_apple_ios_sim::target(),
        // Note: There is currently no ARM64 tvOS simulator target
        aarch64_apple_watchos_sim::target(),
    ];

    for target in all_sim_targets {
        assert_eq!(target.abi, "sim")
    }
}

#[test]
fn macos_link_environment_unmodified() {
    let all_macos_targets = [
        aarch64_apple_darwin::target(),
        i686_apple_darwin::target(),
        x86_64_apple_darwin::target(),
    ];

    for target in all_macos_targets {
        // macOS targets should only remove information for cross-compiling, but never
        // for the host.
        assert_eq!(target.link_env_remove, cvs!["IPHONEOS_DEPLOYMENT_TARGET"]);
    }
}

#[test]
fn macos_linker_flags_are_set() {
    let all_macos_targets = [
        aarch64_apple_darwin::target(),
        i686_apple_darwin::target(),
        x86_64_apple_darwin::target(),
    ];

    for target in all_macos_targets {
        // These don't matter beyond seperating M1 from previous CPUs
        let arch = if target.arch == "aarch64" { Arch::Arm64 } else { Arch::X86_64 };

        let expected_deployment_target = super::macos_deployment_target(arch);
        let expected_deployment_target =
            format!("{}.{}", expected_deployment_target.0, expected_deployment_target.1);

        // Make sure the deployment target influences the LLVM target
        assert!(
            target.llvm_target.strip_suffix(".0").unwrap().ends_with(&expected_deployment_target)
        );

        let expected_args = [
            "-platform_version",
            "macos",
            expected_deployment_target.as_str(),
            expected_deployment_target.as_str(),
        ];

        let lld_args = target
            .pre_link_args
            .get(&LinkerFlavor::Darwin(Cc::No, Lld::Yes))
            .expect("expected platform version to be set for darwin target using LLD");
        let generics_args = target.pre_link_args.get(&LinkerFlavor::Darwin(Cc::No, Lld::No)).expect("expected platform version to be set for darwin target with no pre-specified linker");

        // Make sure the deployment target is passed to Apple's linkers as the platform version as well
        assert_eq!(&lld_args[2..], expected_args);
        assert_eq!(generics_args[2..], expected_args);
    }
}
