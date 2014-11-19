<?php
	namespace Security;
	
	class ZZFile extends ProtectedResource {

		const OBJECT_IDENTIFIER = 'ZZFile';

		public static function getObjectByID($oid){
			return self::getFileByID($oid);
		}

		public static function getFileByID($file_id){
			$file = new ZZFile;
			$sql = "SELECT * FROM ZZFile as f
						WHERE f.fileid = :fileid";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":fileid" => $file_id));
			
			while($row = $sth->fetch(Connection::FETCH_ASSOC)) {
				foreach ($row as $key => $value)
					$file->$key = $value;
				$file->getPerms();
			}

			return $file->isExist() ? $file : false;
		}

		public static function getFileByPath($path){
			$file = new ZZFile;
			$sql = "SELECT * FROM ZZFile as f
						WHERE lower(f.absolutePath) = :abspath";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":abspath" => strtolower($path)));

			while($row = $sth->fetch(Connection::FETCH_ASSOC)) {
				foreach ($row as $key => $value)
					$file->$key = $value;
				$file->getPerms();
			}


			// #######  folder parse #########
			if (!$file->isExist()){
				while(strpos($path, "\\") !== false) {
					$path = substr($path, 0, strrpos($path, "\\"));
					$temp = self::getFileByPath($path);

					if ($temp instanceOf ZZFile && $temp->isExist()) {
						$file = $temp;
						break;
					}
				}
			}

			return $file->isExist() ? $file : false;
		}

		public static function getCurrentFile(){
			// echo $_SERVER['SCRIPT_FILENAME'];
			return self::getFileByPath($_SERVER['SCRIPT_FILENAME']);
		}

		public static function createObject($object_data) {

			$sql = "INSERT INTO ZZFile (fileName,filePath, fileDesc, folder, absolutePath, specialAccess) 
						VALUES (:filename,:filepath,:filedesc,:folder,:absolutepath,:specialaccess) ";
			$db = Connection::init();
			$q = $db->prepare($sql);

			$q->bindParam(":filename", $object_data['filename']);
			$q->bindParam(":filepath", $object_data['filepath']);
			$q->bindParam(":filedesc", $object_data['filedesc']);
			$q->bindParam(":absolutepath", $object_data['absolutepath']);

			$q->bindParam(":folder", $object_data['folder'], Connection::PARAM_INT);
			$q->bindParam(":specialaccess", implode(",", $object_data['specialaccess']));

			// var_dump($object_data);

			$q->execute(); 
			return self::getFileByID($db->lastInsertId());

		}

		public static function updateObject($id, $object_data) {
			if (!$id || !is_array($object_data)) return false;

			$sql = "UPDATE ZZFile SET fileName = :filename, 
						filePath = :filepath, 
						fileDesc = :filedesc, 
						absolutePath = :absolutepath, 
						folder = :folder, 
						specialAccess = :specialaccess 
					WHERE fileID = :id ";


			// echo $sql;

			$db = Connection::init();
			// $db->setAttribute(Connection::ATTR_EMULATE_PREPARES, true);
			$q = $db->prepare($sql);

			// var_dump($object_data);

			$q->bindParam(":filename", $object_data['filename']);
			$q->bindParam(":filepath", $object_data['filepath']);
			$q->bindParam(":filedesc", $object_data['filedesc']);
			$q->bindParam(":absolutepath", $object_data['absolutepath']);

			$q->bindParam(":folder",  $object_data['folder'], Connection::PARAM_INT);
			
			if (isset($object_data['specialaccess']) && is_array($object_data['specialaccess']))
				$q->bindValue(":specialaccess", implode(",", $object_data['specialaccess']));
			else
				$q->bindValue(':specialaccess', null, Connection::PARAM_INT);
				

			$q->bindParam(":id", $id, Connection::PARAM_INT);

			// $q->debugdumpparams();


			$q->execute(); 
			$db = null;
			return self::getFileByID($id);

		}


		public static function deleteObject($id){
			$sql = "DELETE FROM ZZFile WHERE fileID = :fileid";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":fileid" => $id));

		}




		function isExist(){
			return isset($this->fileID) ? true : false;
		}

		public function getID(){
			return $this->isExist() ? $this->fileID : false;
		}

		public function getFields(){
			return array('fileID' => 'ID', 'fileName' => 'Name', 'fileDesc' => 'Description');
		}


		protected function hasPermCallback($user) {
			return $this->checkSpecialAccess($user->getID());
		}

		protected function checkSpecialAccess ($userid) {
			if (isset($this->specialAccess) && strlen($userid) > 0 ) {
				$spusr = explode(",", $this->specialAccess);
				if (array_search((string)$userid, $spusr) !== false)
					return true;
				else
					return false;
			} else
				return false;
		}

	}


?>