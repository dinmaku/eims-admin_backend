-- Create supplier_social_media table
CREATE TABLE IF NOT EXISTS supplier_social_media (
    social_media_id INTEGER NOT NULL DEFAULT nextval('supplier_social_media_social_media_id_seq'::regclass),
    supplier_id INTEGER NOT NULL,
    platform VARCHAR(100) NOT NULL,
    handle VARCHAR(255) NOT NULL,
    url VARCHAR(255),
    CONSTRAINT supplier_social_media_pkey PRIMARY KEY (social_media_id),
    CONSTRAINT supplier_social_media_supplier_id_fkey FOREIGN KEY (supplier_id)
        REFERENCES suppliers(supplier_id) ON DELETE CASCADE
);

    -- Table for storing event package configurations
CREATE TABLE IF NOT EXISTS event_package_configurations (
    config_id SERIAL PRIMARY KEY,
    events_id INTEGER NOT NULL,
    package_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (events_id) REFERENCES events(events_id),
    FOREIGN KEY (package_id) REFERENCES event_packages(package_id)
);

-- Table for storing configured suppliers from the package
CREATE TABLE IF NOT EXISTS event_package_suppliers (
    id SERIAL PRIMARY KEY,
    config_id INTEGER NOT NULL,
    supplier_id INTEGER NOT NULL,
    original_price DECIMAL(10,2),
    modified_price DECIMAL(10,2),
    is_modified BOOLEAN DEFAULT false,
    is_removed BOOLEAN DEFAULT false,
    remarks TEXT,
    FOREIGN KEY (config_id) REFERENCES event_package_configurations(config_id),
    FOREIGN KEY (supplier_id) REFERENCES suppliers(supplier_id)
);

-- Table for storing configured services from the package
DROP TABLE IF EXISTS event_package_services CASCADE;
CREATE TABLE IF NOT EXISTS event_package_services (
    event_package_service_id SERIAL PRIMARY KEY,
    package_id INTEGER NOT NULL,
    package_service_id INTEGER NOT NULL,
    CONSTRAINT idx_event_package_services UNIQUE (package_id, package_service_id),
    CONSTRAINT fk_event_package FOREIGN KEY (package_id) 
        REFERENCES event_packages(package_id) ON DELETE CASCADE,
    CONSTRAINT fk_package_service FOREIGN KEY (package_service_id) 
        REFERENCES package_service(package_service_id) ON DELETE CASCADE
);

-- Table for storing configured outfits from the package
CREATE TABLE IF NOT EXISTS event_package_outfits (
    id SERIAL PRIMARY KEY,
    config_id INTEGER NOT NULL,
    outfit_id INTEGER,
    gown_package_id INTEGER,
    original_price DECIMAL(10,2),
    modified_price DECIMAL(10,2),
    is_modified BOOLEAN DEFAULT false,
    is_removed BOOLEAN DEFAULT false,
    remarks TEXT,
    FOREIGN KEY (config_id) REFERENCES event_package_configurations(config_id),
    FOREIGN KEY (outfit_id) REFERENCES outfits(outfit_id),
    FOREIGN KEY (gown_package_id) REFERENCES gown_packages(gown_package_id)
);

-- Table for storing additional (non-package) items
CREATE TABLE IF NOT EXISTS event_additional_items (
    id SERIAL PRIMARY KEY,
    events_id INTEGER NOT NULL,
    item_type VARCHAR(50) NOT NULL, -- 'supplier', 'service', 'outfit'
    item_id INTEGER NOT NULL,
    price DECIMAL(10,2),
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (events_id) REFERENCES events(events_id)
);

-- Table for storing wishlist packages
CREATE TABLE IF NOT EXISTS wishlist_packages (
    wishlist_id SERIAL PRIMARY KEY,
    events_id INTEGER NOT NULL,
    package_name character varying NOT NULL,
    capacity integer,
    description character varying(225),
    venue_id integer,
    gown_package_id integer,
    additional_capacity_charges numeric(10,2) DEFAULT 0,
    charge_unit integer DEFAULT 1,
    total_price numeric(10,2),
    created_at date DEFAULT CURRENT_DATE,
    event_type_id integer,
    status character varying(225),
    venue_status character varying(225) DEFAULT 'Pending',
    CONSTRAINT fk_wishlist_event FOREIGN KEY (events_id) 
        REFERENCES events(events_id) ON DELETE CASCADE,
    CONSTRAINT fk_wishlist_venue FOREIGN KEY (venue_id) 
        REFERENCES venues(venue_id) ON DELETE SET NULL,
    CONSTRAINT fk_wishlist_gown_package FOREIGN KEY (gown_package_id) 
        REFERENCES gown_package(gown_package_id) ON DELETE SET NULL,
    CONSTRAINT fk_wishlist_event_type FOREIGN KEY (event_type_id) 
        REFERENCES event_type(event_type_id) ON DELETE SET NULL
);

-- Table for storing wishlist package services
CREATE TABLE IF NOT EXISTS wishlist_package_services (
    wishlist_service_id SERIAL PRIMARY KEY,
    wishlist_id INTEGER NOT NULL,
    package_service_id INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'Pending',
    has_been_updated BOOLEAN DEFAULT FALSE,
    CONSTRAINT idx_wishlist_package_services UNIQUE (wishlist_id, package_service_id),
    CONSTRAINT fk_wishlist_package FOREIGN KEY (wishlist_id) 
        REFERENCES wishlist_packages(wishlist_id) ON DELETE CASCADE,
    CONSTRAINT fk_wishlist_package_service FOREIGN KEY (package_service_id) 
        REFERENCES package_service(package_service_id) ON DELETE CASCADE
);

-- Table for storing wishlist suppliers
CREATE TABLE IF NOT EXISTS wishlist_suppliers (
    id SERIAL PRIMARY KEY,
    wishlist_id INTEGER NOT NULL,
    supplier_id INTEGER NOT NULL,
    price DECIMAL(10,2),
    remarks TEXT,
    status VARCHAR(50) DEFAULT 'Pending',
    has_been_updated BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (wishlist_id) REFERENCES wishlist_packages(wishlist_id) ON DELETE CASCADE,
    FOREIGN KEY (supplier_id) REFERENCES suppliers(supplier_id)
);

-- Table for storing wishlist outfits
CREATE TABLE IF NOT EXISTS wishlist_outfits (
    id SERIAL PRIMARY KEY,
    wishlist_id INTEGER NOT NULL,
    outfit_id INTEGER,
    gown_package_id INTEGER,
    price DECIMAL(10,2),
    remarks TEXT,
    status VARCHAR(50) DEFAULT 'Pending',
    has_been_updated BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (wishlist_id) REFERENCES wishlist_packages(wishlist_id) ON DELETE CASCADE,
    FOREIGN KEY (outfit_id) REFERENCES outfits(outfit_id),
    FOREIGN KEY (gown_package_id) REFERENCES gown_packages(gown_package_id)
);

-- Add venue_status column to wishlist_packages if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_name = 'wishlist_packages' AND column_name = 'venue_status'
    ) THEN
        ALTER TABLE wishlist_packages ADD COLUMN venue_status character varying(225) DEFAULT 'Pending';
    END IF;
END $$;

-- Create invoices table if not exists
CREATE TABLE IF NOT EXISTS invoices (
    invoice_id SERIAL PRIMARY KEY,
    events_id INTEGER NOT NULL REFERENCES events(events_id) ON DELETE CASCADE,
    invoice_number VARCHAR(50) NOT NULL,
    invoice_date DATE NOT NULL,
    total_amount DECIMAL(10, 2) NOT NULL,
    discount_amount DECIMAL(10, 2) DEFAULT 0.00,
    final_amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'Unpaid',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create discounts table if not exists
CREATE TABLE IF NOT EXISTS discounts (
    discount_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    type VARCHAR(20) NOT NULL CHECK (type IN ('percentage', 'fixed')),
    value DECIMAL(10, 2) NOT NULL,
    code VARCHAR(50),
    start_date DATE,
    end_date DATE,
    minimum_purchase DECIMAL(10, 2) DEFAULT 0.00,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create payments table if not exists
CREATE TABLE IF NOT EXISTS payments (
    payment_id SERIAL PRIMARY KEY,
    invoice_id INTEGER NOT NULL REFERENCES invoices(invoice_id) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL,
    payment_method VARCHAR(50) NOT NULL,
    reference_number VARCHAR(100),
    payment_date DATE NOT NULL,
    recorded_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for faster invoice lookup by event
CREATE INDEX IF NOT EXISTS idx_invoices_events_id ON invoices(events_id);

-- Create index for faster payment lookup by invoice
CREATE INDEX IF NOT EXISTS idx_payments_invoice_id ON payments(invoice_id);
