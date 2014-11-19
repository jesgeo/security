<?php
namespace Security;

class Config {
	
	protected $db = null;
	public function __construct(){
		// include ("DatabaseConnection.php");
		$this->db = new Connection;
		$this->initConfig();		
	}
	
	public function getSetting($name){
		$sql = "SELECT * FROM ZZConfig WHERE setting_name = '$name';";
		$rs = $this->db->Execute($sql);
		if ($rs == null || $rs->EOF) 
			return false;
		else
			return $rs->Fields['setting_value']->Value;
	}
	
	public function setSetting($name, $value){
		$sql = "UPDATE ZZConfig SET setting_value = '$value' WHERE setting_name = '$name';";
		
		if ($this->Database->connection->Execute($sql))
			return true;
		else
			return false;
	}
	
	/** 
	  *	Gets config information from the database
	  *	
	*/
	public function initConfig() {
		$sql = "SELECT * FROM ZZConfig;";
		$rs = $this->db->Execute($sql);
		while ($rs != null && !$rs->EOF) {
			define("Security\\".$rs->Fields['setting_name']->Value, $rs->Fields['setting_value']->Value);
			$rs->MoveNext();
		}
	}

}

?>