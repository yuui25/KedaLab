INSERT INTO users (username,password,tenant,role) VALUES
('alice','alice','tenant-a','user'),
('bob','bob','tenant-a','admin'),
('carol','carol','tenant-b','user');

INSERT INTO products (sku,name,price,stock) VALUES
('KM-001','Keda Coffee Beans',1800,30),
('KM-002','Keda Hoodie',6800,12),
('KM-003','Keda Sticker Pack',500,200);

INSERT INTO orders (tenant,buyer_user_id,product_id,quantity,total,status,note,flag,created_at) VALUES
('tenant-a',1,1,2,3600,'pending','fast shipping',NULL,strftime('%s','now')),
('tenant-a',2,2,1,6800,'paid','priority delivery','kedaLab{order_access_boundary}',strftime('%s','now')),
('tenant-b',3,3,5,2500,'pending','gift wrap',NULL,strftime('%s','now'));
