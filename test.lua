fw = require("fw");
edcl_init();

local bootheader_magic_host_image_valid = 0xdec0efbe
local im0 = 0x00040000

fw.run_code = function(file, slavemode)
  if (edcl_upload(im0, file) == -1) then
    error("Failed to upload file or no file found!")
  end
end

fw.run_code("/home/user/hello_world.img");

edcl_write(4, im0, bootheader_magic_host_image_valid)
