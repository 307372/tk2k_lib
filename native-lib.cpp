#include <jni.h>
#include <string>
#include <cassert>
#include <sstream>
#include "archive.h"

static Archive archive;
static IntegrityValidation iv;
static bool abortingVariable = false;
static uint32_t totalProgress = 0;
static uint32_t partialProgress = 0;



namespace testing {
    void createTestArchive(Archive &archive, const std::string &filePath, const std::string &archivePath)
    {
        std::bitset<16> flags{0};
        flags.set(15); // SHA-1
        flags.set(0); // BWT (DC3)
        flags.set(1); // MTF
        flags.set(2); // RLE
        //flags.set(3); // AC (naive)
        //flags.set(4); // AC (better)
        flags.set(5); // rANS
        flags.set(10); // divide block size 4x
        uint16_t flags_num = (uint16_t) flags.to_ulong();
        archive.add_file_to_archive_model(std::ref(archive.root_folder), filePath, flags_num);


        bool fakeAbortingVar = false;
        archive.save(archivePath, fakeAbortingVar);
    }

    void createOneFolderArchive(const std::string &archivePath) {
        archive.add_folder_to_model(archive.root_folder, "test folder");

        bool fakeAbortingVar = false;
        archive.save(archivePath, fakeAbortingVar);
    }

    void createComplexTestArchive(
            Archive &archive,
            const std::string &filePath1,
            const std::string &filePath2,
            const std::string &filePath3,
            const std::string &archivePath)
    {
        // all pointers in root folder and root file must be filled

        std::bitset<16> flags{0};
        flags.set(15); // SHA-1
        flags.set(0); // BWT (DC3)
        flags.set(1); // MTF
        flags.set(2); // RLE
        //flags.set(3); // AC (naive)
        //flags.set(4); // AC (better)
        flags.set(5); // rANS
        flags.set(10); // divide block size 4x


        uint16_t flags_num = (uint16_t) flags.to_ulong();
        archive.add_file_to_archive_model(std::ref(archive.root_folder), filePath1, flags_num);
        archive.add_file_to_archive_model(std::ref(archive.root_folder), filePath2, flags_num);

        std::shared_ptr<Folder>* folder = archive.add_folder_to_model(archive.root_folder, "test folder");
        archive.add_file_to_archive_model(*folder, filePath3, flags_num);


        bool fakeAbortingVar = false;
        archive.save(archivePath, fakeAbortingVar);
    }

    bool isTheSameData(std::string pathToFile1, std::string pathToFile2) {
        bool abortingVar = false;
        std::string hash1 = iv.get_SHA256_from_file(pathToFile1, abortingVar);
        std::string hash2 = iv.get_SHA256_from_file(pathToFile2, abortingVar);
        return hash1 == hash2;
    }

    std::string isTheSameVisual(std::string pathToFile1, std::string pathToFile2) {
        bool abortingVar = false;
        std::string hash1 = iv.get_SHA256_from_file(pathToFile1, abortingVar);
        std::string hash2 = iv.get_SHA256_from_file(pathToFile2, abortingVar);
        return "\nExpected: " + hash1 + "\nReceived: " + hash2 + "\n\n" +
               (hash1 == hash2 ? "Success" : "Failure") + "\n";
    }

    void createEmptyTextFile() {
        std::string filePath = "/storage/emulated/0/Download/empty.txt";
        std::fstream stream;
        stream.open(filePath, std::ios::out);
        stream.close();
    }

    std::string validateIntegrityValidation() {

        bool abortingVar = false;
        std::stringstream ss;
        ss
                << "SHA\nEmpty:\nExpected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nReceived: ";
        ss << iv.get_SHA256_from_file("/storage/emulated/0/Download/empty.txt", abortingVar);
        ss
                << "\n\"Test\":\nExpected: 532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25\nReceived: ";
        ss << iv.get_SHA256_from_file("/storage/emulated/0/Download/text.txt", abortingVar);

        return ss.str();
    }

    std::string testBasic() {
        std::string name = "text.txt";
        std::string archiveName = "archive";
        std::string dirPath = "/storage/emulated/0/Download/";
        std::string fileLocation = dirPath + name;
        std::string archivePath = dirPath + archiveName + ".tk2k";
        std::string unpackedPath = dirPath + "unpacked/";
        std::string unpackedFilePath = unpackedPath + "archive/" + name;

        createTestArchive(archive, fileLocation, archivePath);

        archive.close();

        archive.load(archivePath);
        bool fakeAbortingVar = false;
        archive.unpack_whole_archive(unpackedPath, archive.archive_file, fakeAbortingVar);
        //bool success = isTheSameData(fileLocation, unpackedFilePath);

        std::string hello = archive.recursive_string()//;//*
                            + "\n" + isTheSameVisual(fileLocation, unpackedFilePath)
                            + "\nsizeof(uint64_t)==" + std::to_string(sizeof(std::uint64_t))
                            + "\n\n" + validateIntegrityValidation();//*/
        return hello.c_str();
    }
    std::string testThings() {
            std::string name = "mozilla";
            std::string archiveName = "archive";
            std::string dirPath = "/storage/emulated/0/Download/";
            std::string fileLocation = dirPath + name;
            std::string archivePath = dirPath + archiveName + ".tk2k";
            std::string unpackedPath = dirPath + "unpacked/";
            std::string unpackedFilePath = unpackedPath + "archive/" + name;

            testing::createTestArchive(archive, fileLocation, archivePath);

            archive.close();

            archive.load(archivePath);
            bool fakeAbortingVar = false;
            archive.unpack_whole_archive(unpackedPath, archive.archive_file, fakeAbortingVar);
            //bool success = isTheSameData(fileLocation, unpackedFilePath);

            std::string output = archive.recursive_string()//;//*
            + "\n" + testing::isTheSameVisual(fileLocation, unpackedFilePath);
            //+ "\nsizeof(uint64_t)==" + std::to_string(sizeof(std::uint64_t));
            //+ "\n\n" + validateIntegrityValidation();//*/
            return output;
    }

    std::string testJustLoad() {
        std::string archiveName = "archive";
        std::string dirPath = "/storage/emulated/0/Download/";
        std::string archivePath = dirPath + archiveName + ".tk2k";

        archive.load(archivePath);

        return archive.recursive_string();
    }

    std::string testJustFolder() {
        std::string archiveName = "archive";
        std::string dirPath = "/storage/emulated/0/Download/";
        std::string archivePath = dirPath + archiveName + ".tk2k";

        createOneFolderArchive(archivePath);
        archive.close();

        archive.load(archivePath);

        return archive.recursive_string();
    }

    std::string testComplex() {
        //Archive archive;
        testing::createEmptyTextFile();
        std::string name1 = "empty.txt";
        std::string name2 = "empty.txt";
        std::string name3 = "empty.txt";
        std::string archiveName = "archive";
        std::string dirPath = "/storage/emulated/0/Download/";
        std::string fileLocation1 = dirPath + name1;
        std::string fileLocation2 = dirPath + name2;
        std::string fileLocation3 = dirPath + name3;
        std::string archivePath = dirPath + archiveName + ".tk2k";
        std::string unpackedPath = dirPath + "unpacked/";
        std::string unpackedFilePath1 = unpackedPath + "archive/" + name1;
        std::string unpackedFilePath2 = unpackedPath + "archive/" + name2;
        std::string unpackedFilePath3 = unpackedPath + "archive/" + name3;

        testing::createComplexTestArchive(archive, fileLocation1, fileLocation2, fileLocation3, archivePath);
        archive.close();

        archive.load(archivePath);
        bool fakeAbortingVar = false;
        archive.unpack_whole_archive(unpackedPath, archive.archive_file, fakeAbortingVar);
        //bool success = isTheSameData(fileLocation, unpackedFilePath);

        std::string output = archive.recursive_string()//;//*
 //                            + "\n\n" + testing::isTheSameVisual(fileLocation1, unpackedFilePath1)
 //                            + "\n\n" + testing::isTheSameVisual(fileLocation2, unpackedFilePath2)
                             + "\n\n" + testing::isTheSameVisual(fileLocation3, unpackedFilePath3);
        //+ "\nsizeof(uint64_t)==" + std::to_string(sizeof(std::uint64_t));
        //+ "\n\n" + validateIntegrityValidation();//*/
        assert(archive.archive_file.is_open());
        return output;
    }
    std::string autoArchiveTest() {
        std::filesystem::path archivePath = "/storage/emulated/0/Download/archive.tk2k";

        if (not std::filesystem::exists(archivePath)) {
            testing::testComplex();
            archive.close();
        }
        return testing::testJustLoad();
    }
}



extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_turbokompresor1999_ArchiveViewActivity_stringFromJNI(JNIEnv *env, jobject thiz) {
    //return env->NewStringUTF(testing::testThings().c_str());
    //return env->NewStringUTF(testing::testComplex().c_str());
    //return env->NewStringUTF(testing::testJustFolder().c_str());
    return env->NewStringUTF(testing::autoArchiveTest().c_str());
}


jbyteArray stringToJniByteArray(JNIEnv *env, std::string str) {
    int byteCount = str.length();
    const jbyte* pNativeMessage = reinterpret_cast<const jbyte*>(str.c_str());
    jbyteArray bytes = env->NewByteArray(byteCount);
    env->SetByteArrayRegion(bytes, 0, byteCount, pNativeMessage);

    return bytes;
}

jobject recursiveFillFileChildren(JNIEnv *env, File* file_ptr);

jobject recursiveFillFolderChildren(JNIEnv *env, Folder* folder_ptr) {
    if (!folder_ptr) return nullptr;
    jclass folderClass = env->FindClass("com/example/turbokompresor1999/Folder");
    jmethodID folderConstructorId = env->GetMethodID(folderClass, "<init>", "([BJ[BLcom/example/turbokompresor1999/Folder;Lcom/example/turbokompresor1999/Folder;Lcom/example/turbokompresor1999/File;)V");
    jobject folderInstance = env->NewObject(folderClass, folderConstructorId,
                                            stringToJniByteArray(env, folder_ptr->name),
                                            (jlong) folder_ptr->lookup_id,
                                            stringToJniByteArray(env, folder_ptr->path.c_str()),
                                            recursiveFillFolderChildren(env, folder_ptr->child_dir_ptr.get()),
                                            recursiveFillFolderChildren(env, folder_ptr->sibling_ptr.get()),
                                            recursiveFillFileChildren(env, folder_ptr->child_file_ptr.get()));
    return folderInstance;
}

jobject recursiveFillFileChildren(JNIEnv *env, File* file_ptr) {
    if (!file_ptr) return nullptr;
    jclass fileClass = env->FindClass("com/example/turbokompresor1999/File");
    jmethodID fileConstructorId = env->GetMethodID(fileClass, "<init>", "([BJ[BSJJLcom/example/turbokompresor1999/File;)V");
    jobject fileInstance = env->NewObject(fileClass, fileConstructorId,
                                          stringToJniByteArray(env, file_ptr->name),
                                          (jlong) file_ptr->lookup_id,
                                          stringToJniByteArray(env, file_ptr->path),
                                          (jshort) file_ptr->flags_value,
                                          (jlong) file_ptr->original_size,
                                          (jlong) file_ptr->compressed_size,
                                          recursiveFillFileChildren(env, file_ptr->sibling_ptr.get()));
    return fileInstance;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_example_turbokompresor1999_Archive_pullWholeArchive(JNIEnv *env, jobject thiz) {
    return recursiveFillFolderChildren(env, archive.root_folder.get());
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_turbokompresor1999_ProcessingActivity_00024ProcessingThread_compressFile(
        JNIEnv *env, jobject thiz, jstring path_to_file, jlong parent_lookup_id, jint flags)
{
    assert(archive.archive_file.is_open());
    abortingVariable = false;
    totalProgress = 0;
    partialProgress = 0;

    std::shared_ptr<ArchiveStructure> parent_structure = archive.jniLookup[parent_lookup_id].lock();
    std::shared_ptr<Folder> parent = std::dynamic_pointer_cast<Folder>(parent_structure);
    assert(parent.get() != nullptr);
    bool success = false;

    const char* utf_path;
    jboolean isCopy;
    utf_path = env->GetStringUTFChars(path_to_file, &isCopy);
    std::string utf_path_string(utf_path);
    env->ReleaseStringUTFChars(path_to_file, utf_path);

    auto file = archive.add_file_to_archive_model(parent, utf_path_string, (uint16_t) flags);
    file->append_to_archive(archive.archive_file, abortingVariable, false, &partialProgress, &totalProgress);
    success = true;

    return success;
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_example_turbokompresor1999_ProcessingActivity_getProcessingProgress(
        JNIEnv *env, jobject thiz)
{
    return partialProgress * 100 + totalProgress;
}