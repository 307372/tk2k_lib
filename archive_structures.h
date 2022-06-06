#ifndef ARCHIVE_STRUCTURES_H
#define ARCHIVE_STRUCTURES_H

#include <string>
#include <fstream>
#include <filesystem>
#include <thread>
#include <vector>

#include "compression.h"
#include "integrity_validation.h"
#include "misc/project_exceptions.h"

template <typename T>
bool is_uninitialized(std::weak_ptr<T> const& weak) {
    using wt = std::weak_ptr<T>;
    return !weak.owner_before(wt{}) && !wt{}.owner_before(weak);
}

struct Folder;

struct ArchiveStructure {
public:
    std::string name = "";                               // structure's name
    std::filesystem::path path = "";
    std::weak_ptr<Folder> parent_ptr{};                   // ptr to parent folder in memory
    uint64_t location=0;                            // absolute location of this file in archive (starts at name_length)
    uint8_t name_length=0;                          // length of file name (in bytes)
    bool ptr_already_gotten = false;                // true - method get_ptrs was already used on it, so it's in the vector
    bool alreadySaved = false;                      // true - Object has already been saved to archive, false - it's only in the model
    int64_t lookup_id = 0;                          // id in Archive's lookup table, for easier navigation from JNI

    ArchiveStructure(
            std::string name,
            uint8_t name_length=0,
            std::weak_ptr<Folder> parent_ptr = std::weak_ptr<Folder>(),
            std::filesystem::path path = "",
            uint64_t location=0,
            bool ptr_already_gotten = false,
            bool alreadySaved = false,
            int64_t lookup_id = 0) :
            name(name),
            path(path),
            parent_ptr(parent_ptr),
            location(location),
            name_length(name_length),
            ptr_already_gotten(ptr_already_gotten),
            alreadySaved(alreadySaved),
            lookup_id(lookup_id) {}

            virtual ~ArchiveStructure(){};
};

struct File;

struct Folder : ArchiveStructure
{
public:
    static const uint8_t base_metadata_size = 33;   // base metadata size (excluding name_size) (in bytes)
    std::shared_ptr<Folder> child_dir_ptr=nullptr;  // ptr to first subfolder in memory
    std::shared_ptr<Folder> sibling_ptr=nullptr;    // ptr to next sibling folder in memory
    std::shared_ptr<File> child_file_ptr=nullptr;   // ptr to first file in memory

    Folder();
    Folder(std::shared_ptr<Folder>& parent, std::string folder_name);
    Folder(std::weak_ptr<Folder> parent, std::string folder_name);

    void recursive_print(std::ostream &os) const;

    friend std::ostream& operator<<(std::ostream& os, const Folder& f);

    void parse(std::fstream &os, uint64_t pos, std::weak_ptr<Folder>& parent, std::shared_ptr<Folder>& shared_this);

    void append_to_archive( std::fstream& archive_file, bool& aborting_var );

    void write_to_archive( std::fstream& archive_file, bool& aborting_var );

    void unpack( const std::filesystem::path& target_path, std::fstream &os, bool& aborting_var, bool unpack_all ) const;

    void copy_to_another_archive( std::fstream& source, std::fstream& destination, uint64_t parent_location, uint64_t previous_sibling_location );

    void get_ptrs( std::vector<Folder*>& folders, std::vector<File*>& files );

    void set_path( std::filesystem::path extraction_path, bool set_all_paths );
};



struct File : ArchiveStructure
{
private:

    bool encrypted = false;                         // tells us whether or not the file is encrypted
    int  encryption = 0;                            // if encrypted == true, here here we'll find information about what cipher was used
    bool locked = false;                            // file is locked if it's encrypted and the correct password hasn't been provided
    std::basic_string<uint8_t> key;                 // if the file is encrypted and unlocked, the key will be here
    std::basic_string<uint8_t> encryption_metadata; // metadata prepended to the encrypted file. Contains no secrets


public:
    enum encryption_types {None, AES_128};          // enum for int encryption
    static const uint8_t base_metadata_size = 43;   // base metadata size (excluding name_size) (in bytes)
    bool alreadyExtracted = false;                  // true - file has already been extracted


    std::shared_ptr<File> sibling_ptr=nullptr;      // ptr to next sibling file in memory

    uint16_t flags_value=0;                         // 16 flags represented as 16-bit int

    uint64_t data_location=0;                       // location of data in archive (in bytes)
    uint64_t compressed_size=0;                     // size of compressed data (in bytes)
    uint64_t original_size=0;                       // size of data before compression (in bytes)
    File();
    ~File();

    bool process_the_file(std::fstream &archive_stream,
                          const std::string& path_to_destination,
                          bool decode,
                          bool& aborting_var,
                          bool validate_integrity = true,
                          uint32_t* partialProgress = nullptr,
                          uint32_t* totalProgress  = nullptr);

    void recursive_print(std::ostream &os) const;

    friend std::ostream& operator<<(std::ostream &os, const File &f);

    void parse(std::fstream &os, uint64_t pos, std::shared_ptr<Folder>& parent);

    bool append_to_archive(std::fstream& archive_file,
                           bool& aborting_var,
                           bool write_siblings = true,
                           uint32_t* partialProgress = nullptr,
                           uint32_t* totalProgress  = nullptr);

    bool write_to_archive(std::fstream& archive_file,
                          bool& aborting_var,
                          bool write_siblings = true,
                          uint32_t* partialProgress = nullptr,
                          uint32_t* totalProgress  = nullptr);

    bool unpack(const std::string& path,
                std::fstream &os,
                bool& aborting_var,
                bool unpack_all,
                bool validate_integrity = true,
                uint32_t* partialProgress = nullptr,
                uint32_t* totalProgress  = nullptr);
    // returns bool which indicates whether decompression was successful

    std::string get_compressed_filesize_str(bool scaled);

    std::string get_uncompressed_filesize_str(bool scaled);

    void copy_to_another_archive(std::fstream& source, std::fstream& destination, uint64_t parent_location, uint64_t previous_sibling_location, uint16_t previous_name_length);

    void get_ptrs(std::vector<File*>& files, bool get_siblings_too = false);

    void set_path(std::filesystem::path extraction_path, bool set_all_paths);

    bool is_locked() const;

    bool is_encrypted() const;

    void prepare_for_encryption(std::string& pw, bool& aborting_var);

    bool unlock(std::string& pw, std::fstream& archive_stream, bool& aborting_var);    // true = unlocked
};

#endif //EXPERIMENTAL_ARCHIVE_STRUCTURES_H
