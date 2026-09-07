import org.gradle.api.attributes.java.TargetJvmVersion
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.maven.publish)
}

group = "com.gorunjinian"
version = "0.1.0"

kotlin {
    // Built with JDK 21 (see the test-classpath note below) but emitting Java 17
    // bytecode, which is what Android consumers can actually load. -Xjdk-release
    // keeps the compiler from linking against APIs newer than 17.
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.add("-Xjdk-release=17")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    // `api`, not `implementation`: consumers must see the secp256k1 types and, more
    // importantly, must pull in a JNI binding of their own (jni-android on Android,
    // jni-jvm on the desktop). Hiding it would leave them with an UnsatisfiedLinkError.
    api(libs.secp256k1)

    testImplementation(libs.junit)
    testImplementation(libs.secp256k1.jni.jvm)
}

// secp256k1-kmp-jni-jvm is published for JVM 21+, so the test classpath is allowed to
// resolve 21+ artifacts. The library's own published metadata stays at 17.
listOf(configurations.testCompileClasspath, configurations.testRuntimeClasspath).forEach { cfg ->
    cfg.configure {
        attributes { attribute(TargetJvmVersion.TARGET_JVM_VERSION_ATTRIBUTE, 21) }
    }
}

tasks.test {
    useJUnit()
    testLogging { events("passed", "skipped", "failed") }
}

mavenPublishing {
    publishToMavenCentral()

    // Sign only where a key is actually available. CI supplies one via
    // ORG_GRADLE_PROJECT_signingInMemoryKey; locally there is none, which keeps
    // publishToMavenLocal working without any GPG config on the machine. Maven
    // Local does not need signatures — only the Central bundle does.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    coordinates("com.gorunjinian", "vaultovich", version.toString())

    pom {
        name.set("Vaultovich")
        description.set("A Kotlin/JVM Bitcoin library for offline signing: BIP-32/39/48/69/174/322/352/370/375, PSBT, descriptors, Taproot, MuSig2 and silent payments. Forked from ACINQ's bitcoin-kmp.")
        url.set("https://github.com/gorunjinian/vaultovich")
        inceptionYear.set("2026")

        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }

        developers {
            developer {
                id.set("gorunjinian")
                name.set("gorunjinian")
                url.set("https://gorunjinian.com")
            }
        }

        scm {
            url.set("https://github.com/gorunjinian/vaultovich")
            connection.set("scm:git:git://github.com/gorunjinian/vaultovich.git")
            developerConnection.set("scm:git:ssh://git@github.com/gorunjinian/vaultovich.git")
        }
    }
}
