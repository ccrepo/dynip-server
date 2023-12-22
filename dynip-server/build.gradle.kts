/*
 * This file was generated by the Gradle 'init' task.
 *
 * This generated file contains a sample Java library project to get you started.
 * For more details take a look at the 'Building Java & JVM projects' chapter in the Gradle
 * User Manual available at https://docs.gradle.org/8.0.2/userguide/building_java_projects.html
 *
 * dynip-server Servlet gradle build file.
 */

plugins {
    // Apply the java-library plugin for API and implementation separation.
    `java-library`
    id("war");
}

java {
    sourceCompatibility = JavaVersion.VERSION_19;
    targetCompatibility = JavaVersion.VERSION_19;
}

tasks.withType(Jar::class) {
}

tasks.javadoc() {
	source = sourceSets["main"].allJava;
        /*destinationDir = File("html/javadoc");*/
        options.memberLevel = JavadocMemberLevel.PRIVATE;
}

tasks.clean() {
        doLast {
        /*File("html/javadoc").delete();*/
    }
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    // Use JUnit test framework.
    testImplementation("junit:junit:4.13.2")

    // This dependency is exported to consumers, that is to say found on their compile classpath.
    compileOnly("org.apache.commons:commons-math3:3.6.1")

    compileOnly("javax.servlet:javax.servlet-api:3.1.0");

    // This dependency is used internally, and not exposed to consumers on their own compile classpath.
    compileOnly("com.google.guava:guava:31.1-jre")
} 

tasks.jar() {
    from("src/main/webapp");
    archiveFileName.set("ipserver.jar");
}

tasks.war() {
    archiveFileName.set("ipserver.war");
}