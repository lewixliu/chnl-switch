/*
 * Author: Marcin Harasimczuk
 * 
 * Read /sys file system in search of wireless device and its driver
 * Print information to standard output, return error code.
 */
int print_device_driver( void )
{
	DIR *device_dir;
	struct dirent *dev_slot;
	
	printf("--------------------------------------------------------\n");
	printf("Device -------------------------------------------------\n");
	printf("--------------------------------------------------------\n");
	
	/* Check if device directory is avalible for reading */
	if(access(DEVICE_DIR, R_OK))
	{
		printf("Cannot access device slot files \n");
		return -1;
	}	
	
	/* Open device directory of PCI bus */
	device_dir = opendir(DEVICE_DIR);
	if(!device_dir)
	{
		printf("Cannot open slot directory \n");
		return -1;
	}
	
 	/* For each device folder in device directory */    
 	while((dev_slot = readdir(device_dir)))
	{	
		int class_file;
		char class_file_path[40];
		char dev_class[8];				

		memset(class_file_path, 0, 40);

		sprintf(class_file_path, DEVICE_DIR"%s/class", dev_slot->d_name); 
		
		/* Check if class file is accesible for reading */
		if(access(class_file_path, R_OK))
			continue;
			
		/* Open class file of device and read 8 byte device code */
		class_file = open(class_file_path, O_RDONLY);
		read(class_file, dev_class, 8);

		/* If device is wireless device do this */
		if(!strncmp(dev_class, wireless_dev, 6))
		{
			DIR *drivers_dir;
			struct dirent *driver;
			char drivers_file_path[57];
		
			sprintf(drivers_file_path, 
				DEVICE_DIR"%s/driver/module/drivers/",
				dev_slot->d_name);
			
			/* Open driver directory of chosen device */
			drivers_dir = opendir(drivers_file_path);
			if(!drivers_dir)
			{
				printf("Cannot access drivers directory\n");
				closedir(drivers_dir);
				return -3;
			}
				
			/* Print names of all driver modules for this device */
			while((driver = readdir(drivers_dir)))
			{
				/* Ommit linux directories ".." and "." */
				if(driver->d_name[0] == '.')
					continue;

				printf("driver module: %s\n", driver->d_name);
				printf("slot: %s\n", dev_slot->d_name);		
			}						
			closedir(drivers_dir);
		}
		close(class_file);
	}
	closedir(device_dir);	
	return 0;
}



