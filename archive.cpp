#include "archive.h"

#include <string>
#include <memory>
#include <fstream>
#include <cassert>
#include <filesystem>
#include <iostream>
#include <utility>
#include <sstream>


Archive::Archive() : root_folder(std::make_shared<Folder>())
{
    AssignJniLookupId(root_folder);
}

Archive::~Archive()
{
    close();
    // root_folder.release(); // NOLINT(bugprone-unused-return-value)
}

void Archive::removeArchive() {
    close();
    if (exists(load_path)) {
        std::filesystem::remove(load_path);
    }
    root_folder = nullptr;
    jniLookup = std::unordered_map<int64_t, std::weak_ptr<ArchiveStructure>>();
}

void Archive::close()
{
    if (this->archive_file.is_open())
        this->archive_file.close();
}

void Archive::removeArchiveObjects(std::vector<std::int64_t>& targets) {
    std::vector<Folder*> folders;
    std::vector<File*> files;

    for (std::int64_t target : targets) {
        std::shared_ptr<ArchiveStructure> currentStructure = jniLookup[target].lock();

        if (dynamic_cast<Folder*>(currentStructure.get())) {
            folders.emplace_back(dynamic_cast<Folder*>(currentStructure.get()));
            folders[folders.size()-1]->ptr_already_gotten = true;
        }
        else if (dynamic_cast<File*>(currentStructure.get())) {
            files.emplace_back(dynamic_cast<File*>(currentStructure.get()));
            files[files.size()-1]->ptr_already_gotten = true;
        }
    }

    for (auto single_folder : folders) single_folder->get_ptrs( folders, files );
    for (auto single_file   : files  ) single_file->get_ptrs( files );

    std::filesystem::path temp_path = std::filesystem::temp_directory_path().append("tk1999_archive.tmp");
    std::fstream dst(temp_path, std::ios::binary | std::ios::out);
    assert(dst.is_open());

    dst.put(0);  // first bit is always 0x0, to make any location = 0 within the archive invalid, like nullptr or sth

    assert(archive_file.is_open());

    root_folder->copy_to_another_archive(archive_file, dst, 0, 0);

    if (archive_file.is_open()) archive_file.close();
    if (dst.is_open()) dst.close();

    std::filesystem::copy_file(temp_path, load_path, std::filesystem::copy_options::overwrite_existing);
    std::filesystem::remove(temp_path);
    for(auto target : targets) jniLookup.erase(target);
}

void Archive::save(const std::string& path_to_file, bool& aborting_var)
{
    assert(!this->archive_file.is_open());
    this->archive_file.open( path_to_file, std::ios::binary|std::ios::out );
    assert(this->archive_file.is_open());

    char* buffer[1] = {nullptr};
    this->archive_file.write( (char*)buffer, 1 ); // making sure location at byte 0 in file is not valid
    this->root_folder->write_to_archive( this->archive_file, aborting_var );
}


void Archive::load(const std::string& path_to_file )
{
    this->load_path = std::filesystem::path( path_to_file );

    this->archive_file.open( path_to_file, std::ios::binary | std::ios::in | std::ios::out );
    assert(this->archive_file.is_open());

    std::weak_ptr<Folder> emptyPtr{};

    this->archive_file.seekg( 1 );
    this->root_folder->parse(this->archive_file, 1, emptyPtr, this->root_folder);
    recursiveAddFolderToLookup(root_folder);

    this->root_folder->name = std::filesystem::path(path_to_file).filename();
    this->root_folder->name_length = this->root_folder->name.length();
}


void Archive::build_empty_archive() const
{
    this->root_folder->name = "new_archive" + this->extension;
    this->root_folder->name_length = this->root_folder->name.length();
    this->root_folder->location = 1;
}


void Archive::build_empty_archive(std::string archive_name)
{
    this->root_folder->name = archive_name;
    this->root_folder->name_length = this->root_folder->name.length();
    this->root_folder->location = 1;
}


std::shared_ptr<File>* find_file_in_archive( Folder* parent, File* wanted_file ) {
    if ( parent->child_file_ptr.get() == wanted_file ) return &(parent->child_file_ptr);

    std::shared_ptr<File>* tempfile_ptr = &(parent->child_file_ptr);
    while( tempfile_ptr->get() != wanted_file and tempfile_ptr->get() != nullptr ) {
        tempfile_ptr = &(tempfile_ptr->get()->sibling_ptr);
    }
    if ( tempfile_ptr->get() == wanted_file ) return tempfile_ptr;

    return nullptr;
}


std::shared_ptr<Folder>* find_folder_in_archive( Folder* parent, Folder* wanted_folder ) {
    if ( parent->child_dir_ptr.get() == wanted_folder ) return &(parent->child_dir_ptr);

    std::shared_ptr<Folder>* tempfolder_ptr = &(parent->child_dir_ptr);
    while( tempfolder_ptr->get() != wanted_folder and tempfolder_ptr->get() != nullptr ) {
        tempfolder_ptr = &(tempfolder_ptr->get()->sibling_ptr);
    }
    if ( tempfolder_ptr->get() == wanted_folder ) return tempfolder_ptr;
    return nullptr;
}


void Archive::unpack_whole_archive( const std::string& path_to_directory, std::fstream &os, bool& aborting_var )
{
    std::filesystem::path path(path_to_directory);
    if (!std::filesystem::exists(path))
        std::filesystem::create_directories( path ); // create missing folders

    assert(this->archive_file.is_open());

    this->root_folder->unpack( path, os, aborting_var, true );

}


std::shared_ptr<Folder>* Archive::add_folder_to_model( std::shared_ptr<Folder> &parent_dir, const std::string& folder_name )
{
    std::shared_ptr<Folder> *pointer_to_be_returned = nullptr;
    if (parent_dir->child_dir_ptr == nullptr) {
        parent_dir->child_dir_ptr = std::make_shared<Folder>( parent_dir, folder_name );
        pointer_to_be_returned = &(parent_dir->child_dir_ptr);
    }
    else {
        Folder* previous_folder = parent_dir->child_dir_ptr.get();
        while( previous_folder->sibling_ptr != nullptr )
        {
            previous_folder = previous_folder->sibling_ptr.get();
        }
        previous_folder->sibling_ptr = std::make_shared<Folder>( parent_dir, folder_name );
        pointer_to_be_returned = &(previous_folder->sibling_ptr);
    }

    return pointer_to_be_returned;
}


Folder* Archive::add_folder_to_model(std::weak_ptr<Folder> parent_dir, std::string folder_name)
{
    assert(not is_uninitialized(parent_dir));
    auto locked_parent = parent_dir.lock();
    std::shared_ptr<Folder> *pointer_to_be_returned = nullptr;
    if (locked_parent->child_dir_ptr == nullptr) {
        locked_parent->child_dir_ptr = std::make_shared<Folder>( parent_dir, folder_name );
        AssignJniLookupId(locked_parent->child_dir_ptr);
        pointer_to_be_returned = &(locked_parent->child_dir_ptr);
    }
    else {
        Folder* previous_folder = locked_parent->child_dir_ptr.get();
        while( previous_folder->sibling_ptr != nullptr )
        {
            previous_folder = previous_folder->sibling_ptr.get();
        }
        previous_folder->sibling_ptr = std::make_shared<Folder>( parent_dir, folder_name );
        AssignJniLookupId(locked_parent->sibling_ptr);
        pointer_to_be_returned = &(previous_folder->sibling_ptr);
    }

    return pointer_to_be_returned->get();
}


std::shared_ptr<File> Archive::add_file_to_archive_model(std::shared_ptr<Folder>& parent_dir, const std::string& path_to_file, const uint16_t& flags)
{
    std::filesystem::path std_path(path_to_file);
    std::shared_ptr<File> new_file = std::make_shared<File>();

    File* ptr_new_file = new_file.get();
    ptr_new_file->path = path_to_file;


    ptr_new_file->name = std_path.filename().string();
    ptr_new_file->name_length = ptr_new_file->name.length();

    ptr_new_file->parent_ptr = parent_dir;            // ptr to parent folder in memory
    ptr_new_file->sibling_ptr=nullptr;                      // ptr to next sibling file in memory

    if (parent_dir->child_file_ptr != nullptr)
    {
        File* file_ptr = parent_dir->child_file_ptr.get();  // file_ptr points to previous file
        while( file_ptr->sibling_ptr != nullptr )
        {
            file_ptr = file_ptr->sibling_ptr.get();
        }
        file_ptr->sibling_ptr.swap(new_file);
        AssignJniLookupId(file_ptr->sibling_ptr);
        new_file = file_ptr->sibling_ptr;
    }
    else {
        parent_dir->child_file_ptr.swap(new_file);
        AssignJniLookupId(parent_dir->child_file_ptr);
        new_file = parent_dir->child_file_ptr;
    }

    correct_duplicate_names(ptr_new_file, parent_dir.get());

    ptr_new_file->flags_value = flags;              // 16 flags represented as 16-bit int
    ptr_new_file->data_location = 0;                // location of data in archive (in bytes) will be added to model right before writing the data
    ptr_new_file->original_size = std::filesystem::file_size( std_path );
    ptr_new_file->compressed_size=0;                // will be determined after compression

    return new_file;
}

void Archive::recursiveAddFolderToLookup(std::shared_ptr<Folder>& folder_ptr) {
    // check if already added or partialy added
    if (folder_ptr->lookup_id == 0) {
        AssignJniLookupId(folder_ptr);
    } else if (jniLookup.find(folder_ptr->lookup_id) == jniLookup.end()) {
        jniLookup[currentLookupId++] = folder_ptr;
    }

    if (folder_ptr->child_dir_ptr) recursiveAddFolderToLookup(folder_ptr->child_dir_ptr);
    if (folder_ptr->sibling_ptr) recursiveAddFolderToLookup(folder_ptr->sibling_ptr);
    if (folder_ptr->child_file_ptr) recursiveAddFileToLookup(folder_ptr->child_file_ptr);

}

void Archive::recursiveAddFileToLookup(std::shared_ptr<File>& file_ptr) {
    // check if already added or partialy added
    if (file_ptr->lookup_id == 0) {
        AssignJniLookupId(file_ptr);
    } else if (jniLookup.find(file_ptr->lookup_id) == jniLookup.end()) {
        jniLookup[currentLookupId++] = file_ptr;
    }

    if (file_ptr->sibling_ptr) recursiveAddFileToLookup(file_ptr->sibling_ptr);
}

/*
File* Archive::add_file_to_archive_model(Folder &parent_dir, const std::string& path_to_file, uint16_t& flags )
{
    std::filesystem::path std_path( path_to_file );
    std::shared_ptr<File> new_file = std::make_shared<File>();
    File* ptr_new_file = new_file.get();
    ptr_new_file->path = path_to_file;


    ptr_new_file->name = std_path.filename().string();
    ptr_new_file->name_length = ptr_new_file->name.length();

    ptr_new_file->parent_ptr = parent_dir;                 // ptr to parent folder in memory
    ptr_new_file->sibling_ptr = nullptr;                    // ptr to next sibling file in memory

    if (parent_dir.child_file_ptr.get() != nullptr)
    {
        File* file_ptr = parent_dir.child_file_ptr.get();   // file_ptr points to previous file
        while( file_ptr->sibling_ptr != nullptr )
        {
            file_ptr = file_ptr->sibling_ptr.get();
        }
        file_ptr->sibling_ptr.swap(new_file);
    }
    else {
        parent_dir.child_file_ptr.swap(new_file);
    }

    ptr_new_file->flags_value = flags;                      // 16 flags represented as 16-bit int
    ptr_new_file->data_location = 0;                        // location of data in archive (in bytes) will be added to model right before writing the data
    ptr_new_file->compressed_size=0;                        // will be determined after compression
    ptr_new_file->original_size = std::filesystem::file_size( std_path );

    return ptr_new_file;
}*/


void Archive::recursive_print() const {
    root_folder->recursive_print( std::cout );
    std::cout << std::endl;
}

std::string Archive::recursive_string() const {
    std::stringstream ss;
    root_folder->recursive_print(ss);
    return ss.str();
}

void Archive::AssignJniLookupId(const std::shared_ptr<ArchiveStructure>& structure)
{
    structure->lookup_id = currentLookupId;
    jniLookup[currentLookupId++] = structure;
}

void Archive::correct_duplicate_names(File* target_file, Folder* parent_folder)
{
    std::vector<std::string> name_list;
    if (parent_folder->child_file_ptr == nullptr) return;
    else {
        File* file_in_dir = parent_folder->child_file_ptr.get();
        name_list.push_back(file_in_dir->name);

        while (file_in_dir->sibling_ptr != nullptr)
        {
            file_in_dir = file_in_dir->sibling_ptr.get();
            name_list.push_back(file_in_dir->name);
        }
        std::string new_name = std::filesystem::path(target_file->name).stem().string() + " (";
        std::string extension = std::filesystem::path(target_file->name).extension().string();
        uint64_t duplicate_counter = 0;
        bool unique_name = false;

        while( !unique_name ) {
            bool found = false;
            uint64_t names_like_current = 0;
            for (auto current_name : name_list)
            {
                if (duplicate_counter == 0)
                {
                    if (target_file->name == current_name)
                    {
                        names_like_current++;
                        if (names_like_current > 1) {
                            duplicate_counter++;
                            found = true;
                            break;
                        }
                    }
                }
                else
                {
                    if(new_name + std::to_string(duplicate_counter) + ")" + extension == current_name)
                    {
                        duplicate_counter++;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) unique_name = true;
        }

        if (duplicate_counter > 0)
        {
            target_file->name = new_name + std::to_string(duplicate_counter) + ")" + extension;
            target_file->name_length = target_file->name.length();
        }
    }
}