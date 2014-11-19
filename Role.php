<?php
	namespace Security;

	class Role {

		protected $permissions;
		protected $db = null;

		protected function __construct(){
			$this->permissions = array();
			$this->db = new Connection;
		}

		// return a role object with associated permissions
		public static function getRoleByID($role_id){
			$role = new Role;
			$sql = "SELECT * FROM ZZGroup as r
						WHERE r.groupID = :roleid";
			$sth = Connection::init()->prepare($sql);

			$sth->execute(array(":roleid" => $role_id));

			while($row = $sth->fetch(Connection::FETCH_ASSOC)) {
				foreach ($row as $key => $value)
					$role->$key = $value;				
				$role->getPerms();
			}

			return $role;
		}

		public static function createObject($object_data){
			$sql = "INSERT INTO ZZGroup (groupname,groupdescription, groupicon, usericon, maintenanceaccess)
						
						VALUES (:groupname,:groupdescription,:groupicon, :usericon, :maintenanceaccess) ";
			$db = Connection::init();
			$q = $db->prepare($sql);

			$q->bindParam(":groupname", $object_data['groupname']);
			$q->bindParam(":groupdescription", $object_data['groupdescription']);
			$q->bindParam(":groupicon", $object_data['groupicon']);
			$q->bindParam(":usericon", $object_data['usericon']);
			$q->bindParam(":maintenanceaccess", $object_data['maintenanceaccess']);
			

			// var_dump($object_data);

			$q->execute(); 
			return self::getRoleByID($db->lastInsertId());
		}

		public static function updateObject($id, $object_data){
			if (!$id || !is_array($object_data)) return false;

			$sql = "UPDATE ZZGroup SET groupname = :groupname, 
						groupdescription = :groupdescription, 
						groupicon = :groupicon, 
						usericon = :usericon, 
						maintenanceaccess = :maintenanceaccess
					WHERE groupID = :id ";


			// echo $sql;

			$db = Connection::init();

			$q = $db->prepare($sql);
			$q->bindParam(":groupname", $object_data['groupname']);
			$q->bindParam(":groupdescription", $object_data['groupdescription']);
			$q->bindParam(":groupicon", $object_data['groupicon']);
			$q->bindParam(":usericon", $object_data['usericon']);
			$q->bindParam(":maintenanceaccess", $object_data['maintenanceaccess'], Connection::PARAM_INT);

			
			$q->bindParam(":id", $id, Connection::PARAM_INT);

			// $q->debugdumpparams();

			$q->execute(); 
			$db = null;
			return self::getRoleByID($id);
		}


		public static function deleteObject($id) {
			$sql = "DELETE FROM ZZGroup WHERE groupID = :uid";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":uid" => $id));
		}

		
		public static function addUserRole($user, $role) {
			$r = self::getRoleByID($role);
			$u = PrivilegedUser::getUserByID($user);

			if($r && $u){
				$sql = "INSERT INTO ZZGroupMember VALUES (:user, :role)";
				$sth = Connection::init()->prepare($sql);
				$sth->execute(array(":user" => $u->getID(), ":role" => $r->getID() ));
			}


		}

		public static function deleteUserRole($user, $role) {
			$r = self::getRoleByID($role);
			$u = PrivilegedUser::getUserByID($user);

			var_dump($r);

			if($r && $u){
				$sql = "DELETE FROM ZZGroupMember where ZZUserID = :user and ZZGroupID = :role";
				echo $sql;
				$sth = Connection::init()->prepare($sql);

				$sth->execute(array( ":user" => $u->getID(), ":role" => $r->getID() ));
			}


		}


		protected function getPerms() {
			$sql = "SELECT p.perm_id, pt.name as type, typeID, object, object_id from role_permission as rp 
						inner join permission as p on rp.perm_id=p.perm_id
						inner join zzpermissiontype pt on pt.typeid=rp.ptype
					where rp.role_id = :roleid";
			$sth = $this->db->prepare($sql);
			$sth->execute(array(":roleid" => $this->groupID));

			while($row = $sth->fetch(Connection::FETCH_ASSOC)) {
				$this->permissions[$row['perm_id']] = $row;
			}

		}

		public function isExist(){
			return isset($this->groupID);
		}

		public function getID(){
			return $this->isExist() ? $this->groupID : false;
		}

		// check if a permission is set
		function hasPerm($permission, $type = null) {
			if (!$type)
				return isset($this->permissions[$permission]);
			return $this->permissions[$permission]['type'] == $type || 
				$this->permissions[$permission]['typeID'] == $type;

		}
	}



?>