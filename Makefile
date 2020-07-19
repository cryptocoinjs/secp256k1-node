.PHONY: build-addon coverage coverage-lcov format format-cpp lint lint-cpp \
	lint-cpp-ci lint-js package package-copy-files package-fix-packagejson \
	package-pack package-copy test test-tap


prebuildify = ./node_modules/.bin/prebuildify
prebuildify-cross = ./node_modules/.bin/prebuildify-cross

# hack, otherwise GitHub Actions for Windows:
#  '.' is not recognized as an internal or external command, operable program or batch file.
build-addon:
	$(prebuildify) --target node@10.0.0 --napi --strip && node -p "process.platform"

build-addon-linux:
	$(prebuildify-cross) -i centos7-devtoolset7 -i alpine --target node@10.0.0 --napi --strip


nyc = ./node_modules/.bin/nyc

coverage:
	RANDOM_TESTS_REPEAT=1 $(nyc) $(tape) $(test_files)

coverage-lcov: coverage
	RANDOM_TESTS_REPEAT=1 $(nyc) report -r lcov


format_cpp_files = ./src/*.cc ./src/*.h

format: format-cpp

format-cpp:
	clang-format -i -verbose $(format_cpp_files)


standard = ./node_modules/.bin/standard
lint_dir = build/lint

lint: lint-cpp lint-js

lint-cpp:
	mkdir -p $(lint_dir)/cpp/src
	rsync -a --delete src/ $(lint_dir)/cpp/src
	cd $(lint_dir)/cpp && clang-format -i -verbose $(format_cpp_files)
	git diff --no-index --exit-code src $(lint_dir)/cpp/src

# `-verbose` not exists in clang-format@3.8
# See https://github.com/actions/virtual-environments/issues/46
lint-cpp-ci:
	clang-format -i $(format_cpp_files)
	git diff --exit-code --color=always

lint-js:
	$(standard)


package_dir = build/package
package_include_dirs = \
	lib \
	prebuilds \
	src
package_include_files = \
	API.md \
	binding.gyp \
	bindings.js \
	elliptic.js \
	index.js \
	LICENSE \
	package.json \
	README.md

package: package-copy-files package-fix-packagejson package-pack package-copy

package-copy-files:
	mkdir -p $(package_dir)
	for loc in $(package_include_dirs); do \
		rsync -a --delete $$loc $(package_dir); \
	done
	cp $(package_include_files) $(package_dir)

package-fix-packagejson:
	./util/package-fix-packagejson.js -f $(package_dir)/package.json

package-pack:
	cd $(package_dir) && npm pack

package-copy:
	cp $(package_dir)/secp256k1-`node -p "require('./package.json').version"`.tgz .


tape = ./node_modules/.bin/tape
tap_reporter = ./node_modules/.bin/tap-dot
test_files = test/index.js

test:
	$(tape) $(test_files) | $(tap_reporter)

# See build-addon
test-tap:
	$(tape) $(test_files) && node -p "process.platform"
