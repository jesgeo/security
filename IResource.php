<?php
	namespace Security;


	interface IResource {

		public static function getObjectByID($object_id);
		public static function createObject($object_data);		
		public static function updateObject($id, $object_data);
		public static function deleteObject($id);

		public function getID();
		public function isExist();

	}

?>