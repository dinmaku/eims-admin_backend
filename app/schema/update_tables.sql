-- Add status column to the wishlist_suppliers table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'wishlist_suppliers' AND column_name = 'status'
    ) THEN
        ALTER TABLE wishlist_suppliers ADD COLUMN status VARCHAR(20) DEFAULT 'Pending';
    END IF;
END
$$;

-- Add status column to the wishlist_outfits table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'wishlist_outfits' AND column_name = 'status'
    ) THEN
        ALTER TABLE wishlist_outfits ADD COLUMN status VARCHAR(20) DEFAULT 'Pending';
    END IF;
END
$$;

-- Add has_been_updated column to wishlist_suppliers if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'wishlist_suppliers' AND column_name = 'has_been_updated'
    ) THEN
        ALTER TABLE wishlist_suppliers ADD COLUMN has_been_updated BOOLEAN DEFAULT FALSE;
    END IF;
END
$$;

-- Add has_been_updated column to wishlist_outfits if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'wishlist_outfits' AND column_name = 'has_been_updated'
    ) THEN
        ALTER TABLE wishlist_outfits ADD COLUMN has_been_updated BOOLEAN DEFAULT FALSE;
    END IF;
END
$$;

-- Add has_been_updated column to wishlist_additional_services if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'wishlist_additional_services' AND column_name = 'has_been_updated'
    ) THEN
        ALTER TABLE wishlist_additional_services ADD COLUMN has_been_updated BOOLEAN DEFAULT FALSE;
    END IF;
END
$$; 