-- Drop the existing foreign key constraint
ALTER TABLE wishlist_packages 
DROP CONSTRAINT IF EXISTS wishlist_packages_gown_package_id_fkey;

-- Add the correct foreign key constraint
ALTER TABLE wishlist_packages
ADD CONSTRAINT wishlist_packages_gown_package_id_fkey 
FOREIGN KEY (gown_package_id) 
REFERENCES gown_package(gown_package_id);

-- Also fix the constraint in wishlist_outfits table if it exists
ALTER TABLE wishlist_outfits
DROP CONSTRAINT IF EXISTS wishlist_outfits_gown_package_id_fkey;

ALTER TABLE wishlist_outfits
ADD CONSTRAINT wishlist_outfits_gown_package_id_fkey
FOREIGN KEY (gown_package_id)
REFERENCES gown_package(gown_package_id);
