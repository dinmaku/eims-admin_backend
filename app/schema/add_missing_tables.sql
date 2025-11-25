-- Create table for wishlist additional services
CREATE TABLE IF NOT EXISTS wishlist_additional_services (
    wishlist_service_id SERIAL PRIMARY KEY,
    wishlist_id INTEGER REFERENCES wishlist_packages(wishlist_id) ON DELETE CASCADE,
    add_service_id INTEGER REFERENCES additional_services(add_service_id),
    price DECIMAL(10,2) DEFAULT 0,
    remarks TEXT,
    status VARCHAR(20) DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add index for better performance
CREATE INDEX IF NOT EXISTS idx_wishlist_additional_services_wishlist_id ON wishlist_additional_services(wishlist_id); 