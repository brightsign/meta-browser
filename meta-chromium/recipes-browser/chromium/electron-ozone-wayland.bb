require electron-gn.inc

RPROVIDES:${PN} = "electron"

REQUIRED_DISTRO_FEATURES = "wayland"

DEPENDS += "\
        libnotify \
        at-spi2-atk \
        virtual/egl \
        wayland \
        wayland-native \
        libffi \
        gtk+3 \
"

GN_ARGS += '\
        ${PACKAGECONFIG_CONFARGS} \
        use_ozone=true \
        ozone_auto_platforms=false \
        ozone_platform_headless=true \
        ozone_platform_wayland=true \
        use_system_wayland_scanner=false \
        use_xkbcommon=true \
        use_system_libwayland=false \
        use_system_minigbm=true \
        use_system_libffi=true \
        use_bundled_fontconfig=false \
        override_electron_version="${PV}" \
        import("//electron/build/args/release.gn") \
'

# The electron binary must always be started with those arguments.
CHROMIUM_EXTRA_ARGS:append = " --ozone-platform=wayland"
