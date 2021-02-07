#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2021 Shun Sakai
#

asciidoctor = find_program('asciidoctor')

man_page = 'rshash.1'

man_page_source = meson.current_source_dir() / '@0@.adoc'.format(man_page)

man_page_target = custom_target(man_page,
    command : [asciidoctor,
        '-a', 'manversion=@0@'.format(meson.project_version()),
        '-b', 'manpage',
        '-D', meson.current_build_dir(),
        '@INPUT@'],
    input : man_page_source,
    install : true,
    install_dir : get_option('mandir') / 'man1',
    output : man_page)

alias_target('man', man_page_target)
