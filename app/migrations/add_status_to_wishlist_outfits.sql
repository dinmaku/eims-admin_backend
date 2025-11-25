-- Add status column if it doesn't exist
DO $$ 
BEGIN 
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name='wishlist_outfits' AND column_name='status'
    ) THEN
        ALTER TABLE wishlist_outfits 
        ADD COLUMN status VARCHAR(50) DEFAULT 'Pending';
    END IF;
END $$; 