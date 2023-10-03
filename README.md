This utility is intended to be used for managing photos and videos, but really works for any kinds of files. It identifies duplicate files, allows you to prune copies, and coalesce them into a single directory.

## Commands

- find - finds all duplicate files (having the same hash) based on the glob passed
- dedup - removes all duplicate files (having the same hash) based on the glob, leaving only one copy.
- coalesce - moves all files based on the glob to a single folder
