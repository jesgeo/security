<?php
	namespace Security;

	class PrivilegedUser {
		
		private $roles;
		
		protected $db = null;
		
		protected $super = false;
		
		/** Creates a new user object, based on the parameter

			@user Array: data with user information
			@user Integer: user id/idonsystem (database)
			@user String: assumes cookie data was passed (database)
			@user NULL: no action
		*/
		public function __construct() {
			$this->db = new Connection;
		}

		public static function getByName($name) {
			$sql = "SELECT * FROM ZZUser where networkUsername = :username";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":username" => $name));
			$result = $sth->fetch(Connection::FETCH_ASSOC);

			if (!empty($result)) {
				$result = array_change_key_case($result);

				$privUser = new PrivilegedUser;
				foreach ($result as $key => $value)
					$privUser->$key = $value;
				
				$privUser->fullname = $result["firstname"]." ".$result["lastname"];
				$privUser->initRoles();
				return $privUser;
			} else {
				return false;
			}
		}


		public static function getUserById($userid){
			$sql = "SELECT * FROM ZZUser where userID = :userid";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":userid" => $userid));
			$result = $sth->fetch(Connection::FETCH_ASSOC);

			if (!empty($result)) {
				$result = array_change_key_case($result);

				$privUser = new PrivilegedUser;
				foreach ($result as $key => $value)
					$privUser->$key = $value;
				
				$privUser->fullname = $result["firstname"]." ".$result["lastname"];
				$privUser->initRoles();
				return $privUser;
			} else {
				return false;
			}
		}

		protected function initRoles(){
			$sql = "SELECT ur.ZZGroupID, r.groupName from ZZGroupMember ur 
						inner join ZZGroup r on r.groupID=ur.ZZGroupID 
					where ur.ZZUserID = :userid";
			$sth = $this->db->prepare($sql);
			$sth->execute(array(":userid" => $this->userid));
			
			$this->roles = array();
			while($row = $sth->fetch(Connection::FETCH_ASSOC)){
				$this->roles[$row['ZZGroupID']] = Role::getRoleByID($row['ZZGroupID']);
			}
		}

		public function isExist(){
			return isset($this->userid);
		}

		public function getID(){
			return $this->isExist() ? $this->userid : false;
		}		

		public function hasPerm($roleid){
			return isset($this->roles[$roleid]);
		}



		public static function createObject($object_data){
			$sql = "INSERT INTO ZZUser (firstname,lastname, networkUsername 
						" . (isset($object_data['idonsystem']) ? ", idonsystem " : "" ) ." ) 
						VALUES (:firstname,:lastname,:networkUsername
							" . (isset($object_data['idonsystem']) ? ", :idonsystem " : "" ) .") ";
			$db = Connection::init();
			$q = $db->prepare($sql);

			$q->bindParam(":firstname", $object_data['firstname']);
			$q->bindParam(":lastname", $object_data['lastname']);
			$q->bindParam(":networkUsername", $object_data['networkusername']);
			
			if( isset($object_data['idonsystem']) )
				$q->bindParam(":idonsystem", $object_data['idonsystem'], Connection::PARAM_INT);

			// var_dump($object_data);

			$q->execute(); 
			return self::getUserById($db->lastInsertId());
		}

		public static function updateObject($id, $object_data){
			if (!$id || !is_array($object_data)) return false;

			$sql = "UPDATE ZZUser SET firstname = :firstname, 
						lastname = :lastname, 
						networkUsername = :networkUsername
						" . (isset($object_data['idonsystem']) ? ", idonsystem = :idonsystem " : "" ) ."
					WHERE userID = :id ";


			// echo $sql;

			$db = Connection::init();

			$q = $db->prepare($sql);
			$q->bindParam(":firstname", $object_data['firstname']);
			$q->bindParam(":lastname", $object_data['lastname']);
			$q->bindParam(":networkUsername", $object_data['networkusername']);

			if( isset($object_data['idonsystem']) )
				$q->bindParam(":idonsystem", $object_data['idonsystem'], Connection::PARAM_INT);
			
			$q->bindParam(":id", $id, Connection::PARAM_INT);

			// $q->debugdumpparams();

			$q->execute(); 
			$db = null;
			return self::getUserById($id);
		}


		public static function deleteObject($id) {
			$sql = "DELETE FROM ZZUser WHERE userID = :uid";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":uid" => $id));
		}

		
		public static function getCurrentUser(){
			return self::getByName(self::getRemoteUserName());
		}

		public static function getRemoteUserName(){
			// strip off domain name if any
			$user = $_SERVER['REMOTE_USER'];
			if (strpos($_SERVER['REMOTE_USER'], "\\") !== false)
				$user = substr($_SERVER['REMOTE_USER'], strpos($_SERVER['REMOTE_USER'], "\\")+1);
			return $user;
		}

	}


	

?>