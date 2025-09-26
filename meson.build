project('secure-exec-server', 'c',
        version : '0.1',
        default_options : ['warning_level=3'])

dep_glib = dependency('glib-2.0')
exe = executable('ses',
                 'src/secure-exec-server.c',
                 dependencies: dep_glib,
                 install : true)

test('basic', find_program('test/test_basic'), is_parallel : false)
test('shutdown', find_program('test/test_shutdown'), is_parallel : false)
