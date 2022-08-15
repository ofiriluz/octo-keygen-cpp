import os
import subprocess
from conans import CMake, ConanFile, tools


class OctoKeygenCPPConan(ConanFile):
    name = "octo-keygen-cpp"
    version = "1.0.0"
    url = "https://github.com/ofiriluz/octo-keygen-cpp"
    author = "Ofir Iluz"
    generators = "cmake"
    settings = "os", "compiler", "build_type", "arch"

    def requirements(self):
        self.requires("octo-logger-cpp@1.0.0")
        self.requires("octo-encryption-cpp@1.0.0")
        self.requires("fmt@9.0.0")
        self.requires("openssl/3.0.5")

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        cmake.test()
        cmake.install()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
