<?php
	namespace Security;

	abstract class ProtectedResource implements IResource {
		
		protected $permissions;
		protected $db; 


		function __construct(){
			$this->db = new Connection;
		}
		
		protected function getPerms(){
			
			$this->permissions = array();

			$sql = "SELECT p.perm_id, role_id, pt.name type from permission p
						inner join role_permission rp on rp.perm_id = p.perm_id
						left join zzpermissiontype pt on pt.typeid = rp.ptype
						where object = :object and object_id = :object_id";
			$sth = $this->db->prepare($sql);
			$sth->execute(array(":object" => static::OBJECT_IDENTIFIER, ':object_id' => $this->getID()));

			while($row = $sth->fetch(Connection::FETCH_ASSOC)) {
				$this->permissions[] = $row;
			}
		}


		protected function hasPermCallback($user){
			return false;
		}

		public function hasPerm($user, $level = false, $callback = false){

			// var_dump($user);
			
			if (!$this->isExist()) return false;
			
			if ($user instanceOf PrivilegedUser) {
				foreach ($this->permissions as $role) {
					if($level && $level != $role['type']) continue;
					if($user->hasPerm($role['role_id']))
						return true;
				}

				if($callback){

				} else {
					if (method_exists($this, "hasPermCallback"))
						return $this->hasPermCallback($user);
					return false;
				}

				return false;
			}
			return false;

		}

		public function getRoles(){
			$roles = array();
			// var_dump($this->permissions);

			foreach ($this->permissions as $role) {
				$roles[] = Role::getRoleByID($role['role_id']);
			}

			return $roles;
		}


		public static function create($data, $roles){

			$o = static::createObject($data);

			// check unique constraint -- object to objectid 

			$sql = "INSERT INTO permission (object, object_id) VALUES (:ob, :obid) ";
			$db = Connection::init();
			$q = $db->prepare($sql);

			$object = static::OBJECT_IDENTIFIER;
			$q->bindParam(":ob", $object);
			$q->bindParam(":obid", $o->getID(), Connection::PARAM_INT);
			$q->execute(); 
			$permid = $db->lastInsertId();
			// echo $permid;

			// insert new roles
			foreach (array_filter($roles) as $rid => $data) {
				$sql = "INSERT INTO role_permission VALUES (:roleid, :permid, :type)";
				$q = $db->prepare($sql);
				$q->bindParam(":roleid", $rid, Connection::PARAM_INT);
				$q->bindParam(":permid", $permid, Connection::PARAM_INT);
				$q->bindParam(":type", $data['type'], Connection::PARAM_INT);
				$q->execute();
			}


			return $o; 
		}

		public static function update($id, $data, $roles){
			$db = Connection::init();
			
			$roles = is_array($roles) ? $roles : array();

			$o = static::updateObject($id, $data);

			// get current role setting
			$sql = "SELECT rp.*, p.perm_id from permission p 
						left join role_permission rp on p.perm_id=rp.perm_id 
					where object = '".static::OBJECT_IDENTIFIER."' 
								and object_id = :id ";
			// echo $sql;

			$sth = $db->prepare($sql);
			$sth->execute(array(":id" => $id));

			$cr = array();			
			while($row = $sth->fetch(Connection::FETCH_ASSOC)){
				$permid = $row['perm_id'];
				if($row['role_id'])
					$cr[$row['role_id']] = Role::getRoleByID($row['role_id']);				
			}

			// delete roles			
			if (count($delete = array_diff(array_keys($cr), array_keys($roles))) > 0){
				$sql = "DELETE FROM role_permission where role_id IN(".implode(",", $delete).") 
							and perm_id = :permid";
				$sth = $db->prepare($sql);
				$sth->execute(array(':permid' => $permid));
			}

			// update current roles 
			array_walk($roles, function(&$v, $k) use ($cr, $permid, $db){
				
				if (isset($cr[$k])) {
					// update permission setting 
					if (!$cr[$k]->hasPerm($permid, $v['type'])) {
						$sql = "update role_permission set ptype = :typeid 
									where role_id = $k and perm_id = $permid";
						$sth = $db->prepare($sql);
						$sth->execute(array(":typeid" => $v['type']));
					}

					$v = false;
				}
			});

			//insert new roles
			foreach (array_filter($roles) as $rid => $data) {	
				$sql = "INSERT INTO role_permission VALUES (:roleid, :permid, :type)";
				$q = $db->prepare($sql);
				$q->bindParam(":roleid", $rid, Connection::PARAM_INT);
				$q->bindParam(":permid", $permid, Connection::PARAM_INT);
				$q->bindParam(":type", $data['type'], Connection::PARAM_INT);
				$q->execute();
			}

			$db = null;

			return $o;
		}

		public static function delete($id){
			$o = static::deleteObject($id);

			// assumes cascade delete on role_permission table
			$sql = "DELETE FROM permission WHERE object = '".static::OBJECT_IDENTIFIER."' 
						and  object_id = :obid";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":obid" => $id));
		}

	}
	

?>