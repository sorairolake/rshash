#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2021 Shun Sakai
#

project('rshash',
    license : 'GPL-3.0-or-later',
    meson_version : '>= 0.52.0',
    version : '0.1.0')

if not (get_option('enable_doc') or get_option('enable_license') or get_option('enable_man'))
    error('Any one of build options must be enabled.')
endif

if get_option('enable_doc')
    doc_files = files('AUTHORS.adoc', 'CONTRIBUTING.adoc', 'INSTALL.adoc', 'README.adoc')
    install_data(doc_files, install_dir : get_option('datadir') / 'doc' / meson.project_name())
endif

if get_option('enable_license')
    license_file = files('COPYING')
    install_data(license_file, install_dir : get_option('datadir') / 'doc' / meson.project_name())
endif

subdir('doc')
