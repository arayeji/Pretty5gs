libcurl_dep = dependency('libcurl', required : true)
threads_dep = dependency('threads', required : true)

# cJSON discovery:
#  1. pkg-config libcjson (Debian/Ubuntu, Fedora, vcpkg, ...).
#  2. fall back to the cJSON copy Open5GS ships in
#     lib/sbi/openapi/external. That copy has been patched by upstream
#     Open5GS to route allocations through ogs_malloc/ogs_free, so
#     when we use it we must also pull libogscore in as a dependency
#     (both for the ogs-core.h include path and for the link).
libcjson_dep = dependency('libcjson', required : false)

open5gs_admin_watcher_sources = [files('src/open5gs_admin_watcher.c')]
open5gs_admin_watcher_extra_inc = []
open5gs_admin_watcher_extra_deps = []
open5gs_admin_watcher_extra_c_args = []

if not libcjson_dep.found()
    message('watcher-c: system libcjson not found, using vendored copy from lib/sbi/openapi/external (requires libogscore)')
    open5gs_admin_watcher_sources += [
        files('../../../lib/sbi/openapi/external/cJSON.c'),
    ]
    open5gs_admin_watcher_extra_inc += [
        include_directories('../../../lib/sbi/openapi/external'),
    ]
    # libcore_dep brings ogs-core.h on the include path and ogscore at
    # link time. libcore_dep is already in scope because
    # top-level meson.build processes subdir('lib') before this file.
    open5gs_admin_watcher_extra_deps += [libcore_dep]
    open5gs_admin_watcher_extra_c_args += ['-DOGS_ADMIN_WATCHER_USE_VENDORED_CJSON']
    # Placeholder so the static_library / declare_dependency lines stay uniform.
    libcjson_dep = declare_dependency()
endif

open5gs_admin_watcher_inc = include_directories('include')

# The watcher uses C99-isms (in-loop variable declarations, designated
# initializers) but the project default is c_std=gnu89. Override for
# this target only — the public header stays C89 compatible so callers
# aren't forced to upgrade.
open5gs_admin_watcher_lib = static_library(
    'open5gs-admin-watcher',
    sources : open5gs_admin_watcher_sources,
    include_directories : [open5gs_admin_watcher_inc] + open5gs_admin_watcher_extra_inc,
    c_args : open5gs_admin_watcher_extra_c_args,
    override_options : ['c_std=gnu11'],
    dependencies : [libcurl_dep, libcjson_dep, threads_dep] + open5gs_admin_watcher_extra_deps,
    install : false,
)

open5gs_admin_watcher_dep = declare_dependency(
    link_with : open5gs_admin_watcher_lib,
    include_directories : open5gs_admin_watcher_inc,
    dependencies : [libcurl_dep, libcjson_dep, threads_dep] + open5gs_admin_watcher_extra_deps,
)
