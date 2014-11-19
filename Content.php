<?php
	namespace Security;

	class Content extends ProtectedResource {
		const OBJECT_IDENTIFIER = 'Content';


		public static function getByID($cid){
			$content = new Content;
			$sql = "SELECT * FROM Content
						WHERE cid = :cid";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":cid" => $cid));
			
			while($row = $sth->fetch(Connection::FETCH_ASSOC)) {
				foreach ($row as $key => $value)
					$content->$key = $value;
				$content->getPerms();
			}
			return $content->isExist() ? $content : false;
		}

		public static function init($name){
			$c = new Content;
			$sql = "SELECT * FROM Content 
						WHERE name = :name";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":name" => $name));

			while($row = $sth->fetch(Connection::FETCH_ASSOC)) {
				foreach ($row as $key => $value)
					$c->$key = $value;
				$c->getPerms();
			}
			return $c;
		}

		public static function chkPerm($name, $level = false){
			$c = self::init($name);
			
			$u = PrivilegedUser::getCurrentUser();

			if ($level)
				return $c->hasPerm($u, $level);
			else
				return $c->hasPerm($u);

		}

		function isExist(){
			return isset($this->cid) ? true : false;
		}

		public function getID(){
			return $this->isExist() ? $this->cid : false;
		}

		public static function getObjectByID($id){
			return self::getByID($id);
		}

		public static function createObject($ob){
			$sql = "INSERT INTO Content (name,[desc]) 
						VALUES (:name,:desc) ";
			$db = Connection::init();
			$q = $db->prepare($sql);

			$q->bindParam(":name", $ob['name']);
			$q->bindParam(":desc", $ob['desc']);

			$q->execute(); 
			return self::getByID($db->lastInsertId());
		}

		public static function updateObject($id, $ob){
			if (!$id || !is_array($ob)) return false;

			$sql = "UPDATE Content SET name = :name, [desc] = :desc
						WHERE cid = :id ";

			$db = Connection::init();
			$q = $db->prepare($sql);

			$q->bindParam(":name", $ob['name']);
			$q->bindParam(":desc", $ob['desc']);

			$q->bindParam(":id", $id, Connection::PARAM_INT);

			$q->execute(); 
			$db = null;
			return self::getByID($id);
		}

		public static function deleteObject($id){
			$sql = "DELETE FROM Content WHERE cid = :cid";
			$sth = Connection::init()->prepare($sql);
			$sth->execute(array(":cid" => $id));
		}



		public function getFields(){
			return array('cid' => 'ID', 'name' => 'Name', 'desc' => 'Description');
		}


	}


?>